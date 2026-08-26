\documentclass{IEEEtran}
\usepackage{cite}
\usepackage{amsmath,amssymb,amsfonts}
\usepackage{algorithmic}
\usepackage{graphicx}
\usepackage{textcomp}
\usepackage{url}
\usepackage{tikz}
\usepackage{float}
\usetikzlibrary{shapes.geometric, arrows.meta, positioning, fit}

\setlength{\parskip}{0.0em}
\def\BibTeX{{\rm B\kern-.05em{\sc i\kern-.025em b}\kern-.08em
    T\kern-.1667em\lower.7ex\hbox{E}\kern-.125emX}}
\begin{document}

\title{Cyberattack Analysis Using Intrusion Alerts and Attack Graphs}
\author{Toby Marsden and Jamie Harrison%
\thanks{Supervised by Mengmeng Ge, Monash University.}}

\maketitle

\begin{abstract}
Security operation centre (SOC) analysts face high volumes of alerts from intrusion detection
systems (IDS), many of which can be false positives. Manually triaging these high volumes
of alerts can lead to alert fatigue, reducing the analysts' ability to effectively identify complex,
multi-stage attacks. Attack graphs offer a structured visualisation of attacker movements
through a system over time and can reduce the burden of alert triage by presenting
correlated intrusion sequences in an interpretable form.

Previous methods of constructing attack graphs required prior expert knowledge of system
vulnerabilities, increasing the necessary resources and prolonging the investigation process,
as well as failing to detect zero-day attacks. We extend SAGE, an existing S-PDFA that
processes IDS alerts, correlates similar alerts into episodes showing a clear timeline of an
attacker's movements, and constructs an interpretable attack graph to visualise the attacker's
movements throughout an entire system.

We address two key limitations of the current implementation. First, SAGE's alert annotation
relies on a manually curated lookup table built for a specific Suricata ruleset; we replace this
with an automated, IDS-agnostic workflow that maps alert signatures to MITRE ATT\&CK
tactics and techniques. Second, SAGE's evaluation approach relies primarily on perplexity,
a metric that fails to measure the structural quality or utility of the generated graphs. To
address this limitation, we introduce a multi-dimensional evaluation approach that
assesses model behaviour, output quality, and alert computation performance.

We expect the automated MITRE mapping to generalise across IDS sources while
maintaining high mapping accuracy when validated against labelled rulesets. The proposed
evaluation method is designed to be reusable beyond SAGE, providing a basis for
comparison in future research.
\end{abstract}

\begin{IEEEkeywords}
Alert Correlation, Attack Graphs, Intrusion Detection Systems, MITRE ATT\&CK, Security Operations Center.
\end{IEEEkeywords}

% -------------------
\section{Introduction}
\label{sec:introduction}

\IEEEPARstart{S}{ecurity} Operations Centre (SOC) analysts face a well-documented
challenge: intrusion detection systems (IDS) generate large volumes of alerts daily, the
majority of which are false positives or low-priority events~\cite{tariq2025,lanigan2025}.
This contributes to alert fatigue, reducing the likelihood of detecting genuine multi-stage
attacks. An attack graph represents malicious progression through a system as a series of
states (Nodes) and transitions (Edges), capturing how individual alerts combine into multi‑step attack
paths and highlighting the possible routes an attacker can take to reach their objectives,
its use offers a structured approach to correlating alerts into coherent attack narratives,
reducing the manual triage burden on analysts.

A key property of attack graphs is their interpretability; which is defined as the extent to which an attack graph’s states, transitions, and overall structure can be easily understood by an analyst, enabling them to reconstruct the attacker’s behaviour without ambiguity. In practice, it determines how clearly the graph communicates the sequence of actions and their meaning in a way that supports reliable human decision making 

\subsection{Literature Review}
\label{sec:litreview}

We followed a systematic approach to conduct a literature review to identify existing alert
correlation and attack graph generation approaches. Papers were identified using keyword
searches across Google Scholar and IEEE Xplore, using terms including:
``intrusion alert driven attack graph'',
``alert correlation attack graph generation'',
``multi-step attack alert correlation'', and
``multi-stage attack graph''.

Papers were included if they met the following criteria: published in 2021 or later; appeared
in a Q1 journal (Scimago) or A/A* conference (CORE ranking); and directly addressed alert
correlation, attack graph generation, or multi-step attack detection. Foundational background
papers predating 2021-the AIF framework~\cite{moskal2020} and
FlexFringe~\cite{verwer2017}-were included as exceptions given their direct relevance to the
SAGE pipeline.
% TODO: "After screening [ ] papers, [ ] were kept for review"

Existing alert correlation approaches fall broadly into four categories, each presenting distinct advantages and disadvantages:

Automata-based methods, for example SAGE~\cite{nadeem2021} \cite{babalau2018} , use probabilistic suffix-based finite automata to learn attack episode sequences directly from IDS alerts, producing interpretable attack graphs without prior vulnerability knowledge. These methods are implemented using Flexfringe \cite{verwer2017}, a passive automaton learning package that applies a state-merging algorithm to construct the S-PDFA; each state encodes Markov chain transition probabilities, meaning the likelihood of the next alert depends only on the current state, allowing the model to capture typical attacker progression patterns from historical alert sequences. However, automata-based methods remain limited by environment-specific alert mappings and lack formal evaluation metrics. 

Graph and deep learning
approaches~\cite{cheng2021,xiao2025,bouguessa2025,wang2024} represent alerts as graph nodes
and apply graph networks, reinforcement or attention-based transformer architectures to
identify structural and temporal dependencies between attack stages.  The learning approaches capture structural and multi-hop dependencies between alerts that attribute-matching methods miss;
however, they are predominantly trained and evaluated on outdated datasets from the late
1990s and early 2000s (DARPA~99, DARPA 2000s), assume labelled training data, and
provide no scalability analysis for real environments.

Similarity and
clustering-based methods~\cite{mao2021,xie2025,meng2024,vanede2022} use semantic embedding and
density-based clustering to aggregate redundant alerts, before reconstructing multistep
attack chains.  These methods improve on raw attribute matching by operating over
semantic embeddings, allowing correlation of alerts with different signatures but similar
meaning, and several integrate MITRE ATT\&CK annotations. The main weaknesses of similarity and clustering-based
approaches are sensitivity to manually-tuned parameters and dependency on
labelled ATT\&CK annotations that are not always available.

Vulnerability-based approaches~\cite{tayouri2023,sadlek2025} generate attack
graphs from known vulnerability databases and map detected alerts to attack graph nodes. These approaches provide logical completeness, outlining all known exploitable
paths in a network and recovering both successful and failed attack chains. However, they
cannot detect novel tactics absent from the vulnerability database, rely on manually crafted
rules, and fail to generalise across network topologies.

A review of the literature reveals several persistent gaps that no approach resolves:
\begin{itemize}
  \item No approach establishes agreed-upon benchmarks or metrics for attack graph
    comparison, making cross-paper comparison impossible.
  \item Evaluation is often conducted on outdated datasets, raising questions about
    applications to modern attacks and IDS signatures.
  \item Standard attack frameworks are inconsistently adopted,
    limiting interoperability.
  \item Interpretability and utility metrics for the resulting attack graphs are inconsistent
    across all reviewed approaches; no paper reviewed measures analyst usefulness or graph
    quality beyond model-level statistics.
\end{itemize}

\subsection{Research Motivation}
\label{sec:motivation}

This project extends SAGE~\cite{nadeem2021} as a suitable foundation for addressing these
gaps. Unlike data-driven approaches that require labelled training data, and
vulnerability-based methods that depend on complete vulnerability knowledge, SAGE
constructs attack graphs directly from raw IDS alerts using an unsupervised automata
learning approach, making it most applicable to real-world SOC environments. We identify
two primary limitations of the current SAGE implementation:
\begin{itemize}
  \item Alert-to-framework (AIF) mappings are hand-coded for the specific Suricata ruleset.
  \item Evaluation relies solely on perplexity score.
\end{itemize}

This project addresses these limitations through three objectives:
(1) a literature review and gap analysis across four alert correlation categories;
(2) an automated pipeline mapping IDS outputs to the MITRE ATT\&CK framework,
replacing the hardcoded mapping with a generalisable approach;
(3) extended evaluation for alert-driven attack graphs incorporating model, results, and
computational evaluation metrics.

This work is guided by the following research questions:
\begin{itemize}
  \item How can alert-driven attack graph generation be extended to improve generalisability
    and evaluability in real-world SOC environments?
  \item How can IDS alert signatures be automatically mapped to a standard attack framework
    without environment-specific configuration?
  \item What metrics can systematically evaluate the quality and utility of alert-driven attack
    graphs beyond perplexity?
\end{itemize}



% -------------------
\section{Methodology}
\label{sec:methodology}

The methodology extends the original SAGE workflow by enhancing its preprocessing and 
evaluation stages.The pipeline retains SAGE’s duplicate filtering, alert correlation,
and S‑PDFA‑based attack‑graph construction, but replaces hardcoded alert annotations
with an IDS‑agnostic MITRE ATT\&CK mapping validated against the Emerging Threats ruleset.
To extend the evaluation metrics beyond perplexity, the approach introduces a multi‑dimensional
evaluation phase including model evaluation, attack graph evaluation and alert computation
evaluation, enabling a more generalisable and systematically evaluable attack‑graph pipeline.
The workflow is described in  Figure~\ref{fig:pipe} .
\begin{figure}[H]
    \centering
    \includegraphics[width=0.7\columnwidth]{ExtendedSAGEPipeline.png}
    \caption{Workflow for alert‑driven attack‑graph generation, showing new contributions, including MITRE ATT\&CK Mapping and evaluation stages, highlighted in blue and inherited SAGE components in grey.}
    \label{fig:pipe}
\end{figure}

\subsection{Dataset Collection}
\label{sec:dataset}

We use the open-source intrusion alert dataset from the original SAGE implementation:
CPTC-2018 (330,270 Suricata alerts across six penetration testing teams), CPTC-2017
(43,611 alerts), and CCDC-2018 (1,052,281 alerts from a blue team exercise). While these
datasets accurately represent multi-stage attack scenarios with different targets, further
datasets may be collected to verify interoperability. Validation of the MITRE mapping pipeline
uses the Emerging Threats ruleset~\cite{emergingthreats}, a publicly available Suricata ruleset
in which rules have MITRE ATT\&CK annotations, serving as a labelled reference set.

\subsection{Pipeline Overview}
\label{sec:pipeline}

We extend SAGE's four-stage pipeline-preprocessing, correlation, construction, and
evaluation. Correlation and construction are unchanged from the original implementation.
Our contributions are confined to preprocessing, where we replace the hardcoded alert
annotations with an automated MITRE ATT\&CK mapping pipeline, and evaluation, where we
introduce a multi-dimensional framework.

\subsubsection{Duplicate Filtering}
Following the original SAGE implementation, alerts with identical attributes occurring within a
one-second threshold are deduplicated; this suppresses noise that would impact model
learning.

\subsubsection{Automated MITRE ATT\&CK Mapping}
The original SAGE implementation maps alert signatures to the AIF framework via a
hardcoded lookup table constructed exclusively for Suricata-specific alerts. As this is
hardcoded, it cannot be transferred to other alert sources without manual redevelopment.

We replace this with an IDS-agnostic mapping pipeline that operates as a one-time setup
step, which extracts alerts from any IDS and maps them to MITRE ATT\&CK tactics and
techniques. This will enable the pipeline to generalise across IDS configurations without
manual redevelopment for each possible IDS.

% TODO: mapping method comparison to be determined -- one semantic approach and one lexical approach

To validate mapping quality, we compare against the Emerging Threats Open
ruleset~\cite{emergingthreats} signatures that carry MITRE ATT\&CK metadata as a labelled
reference set, measuring the proportion of signatures that are correctly mapped to their
expected technique.

\subsubsection{Severity Configuration}
SAGE's episode segmentation relies on severity tiers; scanning is assigned low severity,
exploitation high, and enabler actions medium-to partition episode sequences at points
where attack severity drops, signalling a new attack. Since these tiers were originally derived
from AIF category assignments, the transition to MITRE ATT\&CK requires configuration. We
suggest a configurable mapping from MITRE ATT\&CK tactics to severity tiers, which will
preserve the original implementation's behaviour.

\subsection{Correlation and Construction}
\label{sec:correlation}

Alert episodes are aggregated and correlated into episode sequences per attacker-victim
pair following the original SAGE approach. Episode subsequences are then fed into
FlexFringe~\cite{verwer2017} to learn the S-PDFA, from which attack graphs are extracted on a
per-victim, per-objective basis. Nadeem et al.~\cite{nadeem2021} can be referred to for full
implementation details.

To illustrate the baseline capabilities of this construction phase prior to our proposed MITRE ATT\&CK integration, Figure~\ref{fig:sage-baseline} demonstrates an outputgenerated by the original SAGE implementation. While structurally sound, the node annotations rely on the original environment-specific ruleset, highlighting the need for our automated MITRE mapping pipeline.

\begin{figure}[H]
    \includegraphics[width=0.75\columnwidth, keepaspectratio]{graph_complex}
    \caption{Example attack graphsproduced by the current SAGE implementation on the
    CPTC-2017 dataset~\cite{nadeem2021}. Node shapes denote action types: oval =
    discovery, dashed rectangle = exploitation, diamond = exfiltration/delivery,
    hexagon = attacker objective. Blue edge annotations show inter-episode timing. This attack graph shows a branching attack graph against victim 10.0.0.56,
    illustrating a simple multi-path progression toward a network DoS objective.}
    \label{fig:sage-baseline}
\end{figure}
\subsection{Evaluation approach}
\label{sec:evaluation}

The current implementation evaluates only on perplexity, the prediction power of the model
used; however, as attack graph construction is not a prediction task, this metric carries
little weight. Our contribution involves introducing three additional evaluation dimensions
across model, results, and computational performance.

\subsubsection{Model Evaluation}
Output variance measures the stability of the generated attack graphs under repeated runs
or minor input perturbations; a well-designed model should produce consistent graphs
across similar alert sequences. Robustness is assessed through noise
injection~\cite{wang2025robustness}-introducing false positive alerts, duplicate sequences, and missing attack
steps-to measure the degree to which resulting attack graphs are distorted by imperfect
IDS output.
% TODO: locate references for noise injection / robustness testing methodology

We will also conduct sensitivity analysis on the model, evaluating how it responds
to changes in its configuration parameters-the S-PDFA is governed by manually tuned
parameters, including deduplication threshold and episode aggregation window. We can
vary each parameter incrementally around its default value and measure the resulting change
in the generated attack graphs, as a model that produces significantly different attack graphs
under minor parameter changes has much weaker reliability.
% TODO: locate references for sensitivity analysis and model reliability in this context

\subsubsection{Results Evaluation}
Alert compression ratio (number of raw alerts divided by number of generated attack graphs)
quantifies the reduction in analyst workload, and directly measures the core utility claim of
the SAGE approach. Graph structural metrics will characterise the complexity and
interpretability of the generated attack graphs: branching factor (edges divided by nodes)
indicates amount of sequences that can occur after a state is reached.
Path linearity (longest path length divided by total edges) reflects how linear or branching
the attack sequence is, and graph density captures how easily an attacker can traverse the network.

\subsubsection{Computational Evaluation}
Alert throughput (alerts processed per second) and total pipeline runtime are recorded on a
fixed hardware baseline to provide a reproducible computational baseline.

The proposed evaluation approach is designed to be reusable beyond SAGE, providing a
basis for consistent cross-approach comparison.




% -------------------
\section{Anticipated Results}
\label{sec:results}

We expect the extended SAGE workflow to deliver several broad improvements in the way alert‑driven attack graphs are generated, interpreted, and evaluated. At a high level, the project aims to demonstrate that automated annotation, combined with a richer evaluation framework, can make attack‑graph–based investigation more practical and more generalisable for real SOC environments. 

\subsection{MITRE ATT\&CK Mapping}
\label{sec:MITRE}
1
By replacing SAGE’s hard coded lookup table with an automated MITRE ATT\&CK mapping pipeline, we anticipate achieving a system that can operate across different IDS sources without manual reconfiguration. This would show that alert‑driven attack graph generation can be decoupled from environment‑specific rulesets and made more adaptable to diverse operational settings. 

We expect that MITRE‑based annotation will produce more coherent episode sequences and attack graphs, as alerts will be grouped according to widely adopted adversarial tactics rather than custom categories. This should lead to attack graphs that better reflect real attacker behaviour and are easier for analysts to interpret. In addition, the use of standardised MITRE ATT\&CK tactics is expected to improve the visual clarity of the resulting graphs, producing node labels that are more meaningful, consistent, and comparable across datasets, enhancing the readability and interpretability of the visualised attack paths.



\subsection{Evaluation Metrics}
\label{sec:Evaluation}

The introduction of model‑level, attack graph output, and alert computation performance metrics is expected to provide a more complete understanding of system behaviour than perplexity alone. We anticipate that this framework will highlight differences between datasets, reveal structural properties of attack graphs, and offer a reusable basis for comparing future approaches. 

Because SOC alert streams are inherently noisy, we expect the extended pipeline to demonstrate resilience to false positives, duplicates, and missing alerts. Even at a high level, we anticipate showing that automata‑based approaches can maintain stable attack‑graph structures under realistic alert conditions.

Finally, we expect the system to remain computationally viable for large datasets, showing that automated mapping and multi‑dimensional evaluation can be integrated without prohibitive overhead. This would support the long‑term goal of making alert‑driven attack graph generation suitable for operational SOC workflows.


% -------------------
\bibliographystyle{IEEEtran}
\bibliography{reference}

\end{document}
