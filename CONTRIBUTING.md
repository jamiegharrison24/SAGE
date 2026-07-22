# Contributing

In this file you can find the information that might be useful if you want to contribute to SAGE. Thank you!

## Pull Request

### Branch strategy

This is a two-person fork (Jamie and Toby). `main` is the integration branch and
the regression ground truth — it must always stay green. Do not commit directly
to `main`.

- Cut a feature branch off `main` for each unit of work, named after its Jira
  ticket, e.g. `feature/KAN-12-mapping-pipeline` or `fix/KAN-14-episode-parity`.
- Open a Pull Request into `main` and request review from the **other team
  member** before merging. Keep PRs scoped to a single ticket where possible.
- Rebase or merge `main` into your branch before requesting review so CI runs
  against current code.
- Do not rewrite or move the `baseline-v1` tag (see `BASELINE.md`).

### No changes in attack graphs

If you introduce some code changes that do not change attack graphs (e.g. refactoring or more test cases), make sure that the regression tests, the sink tests and the Python tests pass. You can find the regression tests and the sink tests (written in Bash and taken from [this repository](https://github.com/jzelenjak/research-project)) in `test-scripts/` directory and the Python tests in the `tests.py` file in the root directory of the repository. These tests can also be run locally before pushing the changes.

Furthermore, you can see PEP 8 errors and warnings in PyCharm or you can also run `pycodestyle --ignore=E501,W503,W504 *.py` and `pycodestyle --ignore=E501,W503,W504 signatures/*.py` (to install the [Python style guide checker](https://pycodestyle.pycqa.org/en/latest/), run `pip install pycodestyle`). The error "E501 line too long" and the warnings "W503 line break occurred before a binary operator" and "W504 line break occurred after a binary operator" are ignored, since addressing them does not improve readability of the code.

Finally, write a Pull Request description and reference the Jira ticket it addresses (e.g. "Addresses KAN-12"). Issue tracking for this project lives on the Jira board, not GitHub Issues. Choose the corresponding label(s), however do *not* select the label `changes-ags` (see below). Request review from the other team member.

### Changes to the attack graphs

Follow the same procedure as above, however **do add a label `changes-ags`**. This will skip the regression tests and only run the sink tests and the Python tests. Since there is no ground truth for the attack graphs, make sure that the changes to the attack graphs make sense. Please carefully describe them in the Pull Request description.

### Changes to the IDs

State IDs in attack graphs depend on state IDs in the S-PDFA, which in turn depend on the episode traces that are passed to FlexFringe. For example, the traces might all be the same, but have a different order, in case of changes to the episode sequence generation. As a result, the attack graphs will be the same, even though the state IDs might be different, resulting in failing regression tests. To avoid this problem, you can add the label `changes-ids` to your Pull Request. This will remove the state IDs when comparing the attack graphs, so it is a way for you to verify that the attack graphs are indeed the same, despite having different state IDs. If you still run into anomalies, you can also set the `changes-ags` label to skip regression tests entirely.

### Adding more test cases

If you want to add new test cases, feel free to do so. For Python tests, you can add them to the `tests.py` file. In addition, you can add the new tests to the GitHub Actions by modifying the `.github/workflows/test.yml` file. The tests, however, need first be approved, see the procedure above.

### The docker branch

The `docker` branch is an upstream (tudelft-cda-lab) artefact and is **not
maintained in this fork**. You do not need to mirror changes to it. CI ignores
the `docker` branch.

## GitHub Actions

The workflow of the GitHub Actions is structured as follows:

1. Dependencies are installed: the required (Python) packages are obtained, and the two versions of SAGE are cloned — the `main` branch of this fork (`jamiegharrison24/SAGE`), which is the regression ground truth, and the branch with the Pull Request. The FlexFringe binary and `spdfa-config.ini` are committed to the repo, so nothing is downloaded.
2. Python style check (PEP 8) is executed on the Python files on the Pull Request branch
3. The environment is prepared: alerts are extracted, the committed `flexfringe` binary is made executable (for both versions of SAGE) and the test scripts are copied to the root directory
4. SAGE version on the main branch is executed on the three datasets (CPTC-2017, CPTC-2018 and CCDC-2018) and the necessary output files are moved to the root directory; this step is skipped when the `changes-ags` label is present on the PR)
5. SAGE version on the Pull Request branch is executed on the same three datasets and the necessary output files are moved to the root directory
6. Regression tests are executed on the resulting attack graphs to make sure that the graphs are the same; this step is skipped when the `changes-ags` label is present on the Pull Request
7. Tests for sinks are executed on the SAGE version on the Pull Request branch; these tests check that the (non-)sinks in the attack graphs are consistent with the (non-)sinks in the FlexFringe's S-PDFA model
8. Python tests are executed on the SAGE version on the Pull Request branch; these tests check the functionality of the code (currently only the episode generation, but more tests might be added in the future)

## Documentation

Feel free to add changes to the documentation in case you can come up with a better wording. Also, don't forget to update the documentation if you change the code in the way that requires updating the documentation (e.g. changing parameters to the methods or changing the files).

## Relevant files

- `sage.py` - the entry point to SAGE, contains alert parsing and filtering as well as some global parameters
- `episode_sequence_generation.py` - the first part of the SAGE pipeline that creates episodes and episode (sub)sequences from the alerts, i.e. from making hyperalert sequences to episode subsequence generation
- `model_learning.py` - the second part of the SAGE pipeline that learns the (S-PDFA) model, i.e. running FlexFringe with the generated episode traces and parsing (traversing) the resulting model to create state sequences
- `ag_generation.py` - the third part of the SAGE pipeline that creates the attack graphs, i.e. converting state sequences into attack graphs
- `plotting.py` - contains the functions that are related to plotting (not needed for running SAGE, but might give more insights into alerts or episodes)
- `signatures/` - contains the mappings for Micro/Macro Attack Stages and alerts signatures (files `alert_signatures.py`, `attack_stages.py`, `mappings.py`)
- `.github/workflows/test.yml` - the file for the workflow
- `test-scripts/` - the Bash scripts used for testing
- `tests.py` - contains the Python tests

