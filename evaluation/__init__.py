"""
A reusable evaluation framework for alert-driven attack graph pipelines.

Built for Task A3 of the SAGE honours extension: recording the `baseline-v1`
reference metrics (attack graph structure, S-PDFA perplexity, runtime) that
every later contribution is measured against.

The package is deliberately **artifact-driven**: it derives every metric from
the files a run leaves on disk (the FlexFringe trace file, the two model JSONs
and the rendered `.dot` attack graphs) plus the run's stdout, rather than by
importing the pipeline. This is not incidental -- the baseline commit
(`20aa5ed`) predates the `pipeline.py` refactor and exposes no importable
pipeline at all, so an import-based harness could not measure the very thing it
exists to measure. Driving the CLI keeps one harness working unchanged across
the baseline and every later branch.

The lower layer is SAGE-agnostic and pure (no subprocesses, no clock, no
network), so it is unit-testable without running the pipeline:

    dot_metrics -- .dot attack graphs             -> per-graph structural metrics
    perplexity  -- FlexFringe model JSON + traces -> perplexity
    alerts      -- raw alert files                -> counts and compression ratios
    compare     -- two runs                       -> distortion measures
    schema      -- the versioned record everything is written into
"""

__all__ = ['schema', 'dot_metrics', 'alerts', 'perplexity', 'compare']

SCHEMA_VERSION = 1
