# **SYNAPSE-S2: Spiking STDP Transformer MCP Server**

SYNAPSE-S2 (Synaptic Plasticity & Spiking Encoding via $S^2$) is an Apple Silicon-optimized Model Context Protocol (MCP) server. It provides local large language models (LLMs) with high-efficiency, associative memory capabilities using a persistent, biologically grounded Spiking Neural Network (SNN) substrate.

Unlike traditional vector similarity retrieval methods, SYNAPSE-S2 runs natively on M-series GPUs, completely eliminating the $O(N^2)$ memory wall of traditional self-attention by implementing the Spiking STDP Transformer ($S^2TDPT$) mathematical framework. It operates as a multiplication-free, addition-only system that embeds query-key correlations directly in synaptic weights using Spike-Timing-Dependent Plasticity (STDP).

## **System Architecture**

The plugin acts as a middleware daemon communicating with local editor interfaces and LLM desktop wrappers via JSON-RPC 2.0 over standard input/output (stdio) channels.

```
+-----------------------------------------------------------+
|                      LOCAL LLM CLIENT                     |
|         (Codex Client / Claude Desktop / Claude Code)     |
+-----------------------------+-----------------------------+
                              |
                              | Invokes Tool Calls (JSON-RPC)
                              v
+-----------------------------------------------------------+
|                FASTMCP MODEL CONTEXT LAYER                |
|             (Native Background Process Daemon)            |
+-----------------------------+-----------------------------+
                              |
                              | Projects prompt embeddings
                              | to sparse sensory spikes
                              v
+-----------------------------------------------------------+
|              SYNAPSE-S2 SPICKING SUBSTRATE                |
|        (Metal-Accelerated Recurrent mlx-snn Model)        |
+-----------------------------------------------------------+
```

## **Hierarchical Neural Network Topology**

The SNN is organized into a multi-tiered hierarchical network designed to route, associate, and gate conceptual activations dynamically.

```
            
                             |
                             v
+-----------------------------------------------------------+
| LAYER 1: Sensory Population (5,000 Neurons)               |
| (Translates dense coordinates to sparse z-score spike top-k) |
|  o   o   o   x   o   o   x   o   x   o   o   o   x   o   o    | <-- Active Spikes (x)
+----------------------------+------------------------------+
                             |
                             | Synaptic Projection (W_syn)
                             v
+-----------------------------------------------------------+
| LAYER 2: Associative Fabric (150,000 Neurons)             |
| (Recurrent synaptic loops modified dynamically via STDP)  |
|      /--- o <=======> o <-------\                         | <-- Plastic Synapses
|     |     ^           ^         |                         |
|     v     |           |         v                         |
|     o <---+           +-------> o                         |
+----------------------------+------------------------------+
                             |
                             | Lateral Spreading Activation
                             v
+-----------------------------------------------------------+
| LAYER 3: Categorical & Concept Groups (25,000 Neurons)    |
| (Prefrontal cortex-inspired contextual gating maps)       |
|   [Concept A]                 [Concept C]     |
+----------------------------+------------------------------+
                             |
                             | High-salience Context Injection
                             v
+-----------------------------------------------------------+
|            LLM REASONING CONTEXT FILTER                   |
+-----------------------------------------------------------+
```

## **Core Mathematical Formulation**

### **1\. Dimension-Independent Population Coding**

Dense embeddings $E$ are mapped into discrete binary spike states $S\_i \\in \\{0, 1\\}$ using coordinate-wise standardized z-scores to ensure consistent representation across varying dimensionality boundaries :

$$Z\_i \= \\frac{E\_i \- \\mu\_E}{\\sigma\_E}$$  
Neurons corresponding to indices within the top-$k$ percentile fire a spike ($S\_i \= 1$), while the remainder stay silent ($S\_i \= 0$).

### **2\. Leaky Integrate-and-Fire (LIF) Dynamics**

Individual neuron potentials are processed dynamically using discrete-time updates :

$$U\[t+1\] \= \\beta \\cdot U\[t\] \+ X\[t+1\] \- S\[t\] \\cdot V\_{\\text{thr}}$$  
where $U$ is the membrane potential, $X$ is the input synaptic current, $\\beta \\in (0,1)$ is the decay factor, and $V\_{\\text{thr}}$ is the constant spike threshold. Updates are strictly immutable to compile efficiently on Apple Silicon GPUs.

### **3\. Asymmetric Temporal STDP**

Rather than storing dense attention matrices, correlation values are updated inside the associative fabric according to biological temporal differences ($\\Delta t$) :

$$\\Delta w \= \\begin{cases} A\_+ \\exp\\left(-\\frac{\\Delta t}{\\tau\_+}\\right) & \\text{if } \\Delta t \> 0 \\\\ \-A\_- \\exp\\left(\\frac{\\Delta t}{\\tau\_-}\\right) & \\text{if } \\Delta t \\le 0 \\end{cases}$$

## **Memory Consolidation and Pruning Lifecycle**

The SNN maintains long-term structural efficiency and manages Apple Silicon VRAM limitations by executing a scheduled multi-phase pruning pipeline.

| Phase | System Process | Core Mathematical Operation | Downstream Cognitive Function |
| :---- | :---- | :---- | :---- |
| Phase 1 | Connection Weight Decay | $W\_{ij} \\leftarrow W\_{ij} \\cdot \\gamma\_{\\text{decay}}$ | Lowers weight values for weak connections |
| Phase 2 | Synaptic Clustering | Density-based connection profiling | Identifies overlapping spiking patterns |
| Phase 3 | Semantic Merging | Mathematical node pooling | Consolidates redundant memory paths |
| Phase 4 | Threshold Rescoring | Adaptive adjustments to $V\_{\\text{thr}}$ | Keeps firing rates in healthy, balanced ranges |
| Phase 5 | Trace Promotion | Long-term Synaptic Facilitation | Moves active traces to persistent storage |
| Phase 6 | Relationship Extraction | Hebbian Distillation | Builds structured semantic connection graphs |
| Phase 7 | Neurogenesis | State re-initialization | Frees up inactive nodes for new memory traces |

## **Hardware Integration Optimization**

By executing directly inside Apple's Unified Memory Architecture via mlx-snn, SYNAPSE-S2 resolves the physical memory limitations that plague CUDA-emulated systems :

* **Metal JIT Acceleration**: Synaptic weight updates are compiled natively into GPU kernels using mx.compile to prevent execution overhead on the CPU.  
* **No-Copy Memory Sharing**: The host CPU pre-processes input embeddings, while the integrated M-series GPU computes the spiking networks inside the same physical RAM, completely avoiding costly PCIe bus data copies.  
* **Footprint Control**: Peak VRAM consumption remains constrained between $61\\text{ MB}$ and $138\\text{ MB}$, compared to the heavy allocations required by traditional tensor frameworks.

## **Verification and Diagnostics**

To verify the transport layer, launch the interactive MCP Inspector interface :

Bash

```
npx @anthropic-ai/mcp-inspector uv run mcp_server.py
```

This verifies the stdio JSON-RPC endpoints and ensures structural tool definitions are fully accessible before registering the server to your primary client environments.

