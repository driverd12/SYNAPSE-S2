import CoreGraphics
import Foundation
import ImageIO
import Vision

private let resultSchema = "synapse-s2.apple-vision-helper-result.v1"
private let featureSchema = "synapse-s2.apple-vision-feature-print.v1"
private let ocrSchema = "synapse-s2.apple-vision-ocr.v1"
private let maximumFeatureElements = 8_192
private let maximumOCRObservations = 128
private let maximumOCRUTF8Bytes = 8_192

private enum HelperFailure: Error {
    case invalidArguments
    case imageUnavailable
    case imageTooLarge
    case serializationFailed
}

private struct Arguments {
    let input: String
    let mode: String
    let maximumEdge: Int
}

private func parseArguments() throws -> Arguments {
    var values: [String: String] = [:]
    var index = 1
    let arguments = CommandLine.arguments
    while index < arguments.count {
        let key = arguments[index]
        guard key.hasPrefix("--"), index + 1 < arguments.count else {
            throw HelperFailure.invalidArguments
        }
        values[key] = arguments[index + 1]
        index += 2
    }
    guard
        let input = values["--input"],
        input.hasPrefix("/"),
        !input.contains("\u{0000}"),
        let mode = values["--mode"],
        ["feature-print", "ocr", "all"].contains(mode),
        let maximumEdgeText = values["--max-edge"],
        let maximumEdge = Int(maximumEdgeText),
        (64...2_048).contains(maximumEdge)
    else {
        throw HelperFailure.invalidArguments
    }
    return Arguments(input: input, mode: mode, maximumEdge: maximumEdge)
}

private func boundedImage(path: String, maximumEdge: Int) throws -> CGImage {
    let url = URL(fileURLWithPath: path, isDirectory: false) as CFURL
    guard let source = CGImageSourceCreateWithURL(url, nil) else {
        throw HelperFailure.imageUnavailable
    }
    let options: [CFString: Any] = [
        kCGImageSourceCreateThumbnailFromImageAlways: true,
        kCGImageSourceCreateThumbnailWithTransform: true,
        kCGImageSourceThumbnailMaxPixelSize: maximumEdge,
        kCGImageSourceShouldCacheImmediately: true,
    ]
    guard let image = CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary) else {
        throw HelperFailure.imageUnavailable
    }
    guard
        image.width > 0,
        image.height > 0,
        image.width <= maximumEdge,
        image.height <= maximumEdge,
        image.width * image.height <= maximumEdge * maximumEdge
    else {
        throw HelperFailure.imageTooLarge
    }
    return image
}

private func explicitLittleEndianFeatureData(_ observation: VNFeaturePrintObservation) throws -> (String, Data) {
    let count = observation.elementCount
    guard count > 0, count <= maximumFeatureElements else {
        throw HelperFailure.imageTooLarge
    }
    var output = Data()
    switch observation.elementType {
    case .float:
        guard observation.data.count == count * MemoryLayout<Float>.size else {
            throw HelperFailure.imageUnavailable
        }
        output.reserveCapacity(observation.data.count)
        observation.data.withUnsafeBytes { raw in
            let values = raw.bindMemory(to: Float.self)
            for value in values {
                var bits = value.bitPattern.littleEndian
                withUnsafeBytes(of: &bits) { output.append(contentsOf: $0) }
            }
        }
        return ("float32", output)
    case .double:
        guard observation.data.count == count * MemoryLayout<Double>.size else {
            throw HelperFailure.imageUnavailable
        }
        output.reserveCapacity(observation.data.count)
        observation.data.withUnsafeBytes { raw in
            let values = raw.bindMemory(to: Double.self)
            for value in values {
                var bits = value.bitPattern.littleEndian
                withUnsafeBytes(of: &bits) { output.append(contentsOf: $0) }
            }
        }
        return ("float64", output)
    default:
        throw HelperFailure.imageUnavailable
    }
}

private func featurePrint(_ image: CGImage) -> [String: Any] {
    let request = VNGenerateImageFeaturePrintRequest()
    let revision: Int
    if #available(macOS 14.0, *) {
        revision = VNGenerateImageFeaturePrintRequestRevision2
    } else {
        revision = VNGenerateImageFeaturePrintRequestRevision1
    }
    request.revision = revision
    request.imageCropAndScaleOption = .scaleFit
    do {
        let handler = VNImageRequestHandler(cgImage: image, options: [:])
        try handler.perform([request])
        guard let observation = request.results?.first else {
            return ["status": "failed", "failure_code": "no-feature-print"]
        }
        let (elementType, bytes) = try explicitLittleEndianFeatureData(observation)
        return [
            "status": "ready",
            "schema": featureSchema,
            "request_revision": revision,
            "element_type": elementType,
            "element_count": observation.elementCount,
            "encoding": "base64-little-endian",
            "data": bytes.base64EncodedString(),
        ]
    } catch {
        return ["status": "failed", "failure_code": "feature-print-request-failed"]
    }
}

private func normalizedOCRLine(_ value: String) -> String {
    value
        .components(separatedBy: .controlCharacters)
        .joined(separator: " ")
        .split(whereSeparator: { $0.isWhitespace })
        .joined(separator: " ")
}

private func prefixWithinUTF8Limit(_ value: String, limit: Int) -> (String, Bool) {
    var output = ""
    var count = 0
    var truncated = false
    for character in value {
        let text = String(character)
        let size = text.lengthOfBytes(using: .utf8)
        if count + size > limit {
            truncated = true
            break
        }
        output.append(character)
        count += size
    }
    return (output, truncated)
}

private func recognizeText(_ image: CGImage) -> [String: Any] {
    let request = VNRecognizeTextRequest()
    request.revision = VNRecognizeTextRequestRevision3
    request.recognitionLevel = .accurate
    request.usesLanguageCorrection = true
    request.automaticallyDetectsLanguage = true
    do {
        let handler = VNImageRequestHandler(cgImage: image, options: [:])
        try handler.perform([request])
        let observations = request.results ?? []
        var lines: [String] = []
        var confidenceTotal: Double = 0
        var accepted = 0
        for observation in observations.prefix(maximumOCRObservations) {
            guard let candidate = observation.topCandidates(1).first else { continue }
            let line = normalizedOCRLine(candidate.string)
            guard !line.isEmpty else { continue }
            lines.append(line)
            confidenceTotal += Double(candidate.confidence)
            accepted += 1
        }
        let joined = lines.joined(separator: "\n")
        let (boundedText, byteTruncated) = prefixWithinUTF8Limit(
            joined,
            limit: maximumOCRUTF8Bytes
        )
        return [
            "status": "ready",
            "schema": ocrSchema,
            "request_revision": VNRecognizeTextRequestRevision3,
            "recognition_level": "accurate",
            "language_correction": true,
            "automatic_language_detection": true,
            "observation_count": accepted,
            "mean_confidence": accepted == 0 ? 0.0 : confidenceTotal / Double(accepted),
            "text": boundedText,
            "truncated": byteTruncated || observations.count > maximumOCRObservations,
        ]
    } catch {
        return ["status": "failed", "failure_code": "ocr-request-failed"]
    }
}

private func run() throws -> [String: Any] {
    let arguments = try parseArguments()
    let image = try boundedImage(path: arguments.input, maximumEdge: arguments.maximumEdge)
    var result: [String: Any] = [
        "schema": resultSchema,
        "provider": "apple-vision",
        "mode": arguments.mode,
        "input_dimensions": ["width": image.width, "height": image.height],
    ]
    var statuses: [String] = []
    if arguments.mode == "feature-print" || arguments.mode == "all" {
        let feature = featurePrint(image)
        result["feature_print"] = feature
        statuses.append(feature["status"] as? String ?? "failed")
    }
    if arguments.mode == "ocr" || arguments.mode == "all" {
        let ocr = recognizeText(image)
        result["ocr"] = ocr
        statuses.append(ocr["status"] as? String ?? "failed")
    }
    if statuses.allSatisfy({ $0 == "ready" }) {
        result["status"] = "ready"
    } else if statuses.contains("ready") {
        result["status"] = "partial"
    } else {
        result["status"] = "failed"
    }
    return result
}

do {
    let result = try autoreleasepool(invoking: run)
    guard JSONSerialization.isValidJSONObject(result) else {
        throw HelperFailure.serializationFailed
    }
    let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([0x0a]))
} catch {
    let failure: [String: Any] = [
        "schema": resultSchema,
        "status": "failed",
        "failure_code": "helper-failed",
    ]
    if let data = try? JSONSerialization.data(withJSONObject: failure, options: [.sortedKeys]) {
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([0x0a]))
    }
    exit(2)
}
