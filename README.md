# SAGE (IntruSion alert-driven Attack Graph Extractor)
Repository to accompany our publications

"SAGE: Intrusion Alert-driven Attack Graph Extractor" at VizSec'21, and

"Alert-driven Attack Graph Generation using S-PDFA" at TDSC'21.

> This repository is a fork (`jamiegharrison24/SAGE`, upstream
> `tudelft-cda-lab/SAGE`) used for an honours extension project. If you're
> contributing to this fork, see the [documentation index](docs/README.md)
> for contributing guidelines, the pinned baseline, and Windows/WSL setup.

## Hassle-free way to run SAGE

Switch to the [`docker` branch](https://github.com/tudelft-cda-lab/SAGE/tree/docker) to download and run SAGE inside a docker container. No additional installations are required in that case. Note: the `docker` branch is an upstream artefact and is not maintained in this fork.

## Run SAGE yourself

### Requires

SAGE runs in a **Linux environment** (native Linux/macOS, or WSL Ubuntu on
Windows — see `WINDOWS_SETUP.md`), since FlexFringe is a Linux binary.

- The FlexFringe binary (`FlexFringe/flexfringe`) and its config
  (`FlexFringe/ini/spdfa-config.ini`) are **already committed to this repo**,
  so a fresh checkout is runnable without building FlexFringe from source. Run
  `./setup.sh` (Linux/WSL/macOS) or `setup.ps1` (Windows) to install the
  remaining dependencies, or install manually:
  - `graphviz` (system package; `dot` must be on PATH), `bc`
  - Python packages from `requirements.txt`: `graphviz`, `requests`, `numpy`, `matplotlib`
- Alert data ships gzipped; decompress before the first run:
  `find alerts/ -type f -name '*.gz' | xargs gunzip`

### Usage
`python sage.py path_to_json_files experiment_name [-h] [-t T] [-w W] [--timerange STARTRANGE ENDRANGE] [--dataset {cptc,other}] [--keep-files]`

**Required positional arguments:**

* `path_to_json_files`: Directory containing intrusion alerts in json format. See `alerts/` for examples of suricata alert datasets.
> Ideal setting: One json file for each attacker/team. Filename considered as attacker/team label.
* `experiment_name`: Custom name for all artefacts.
> Figures, trace files, model files, attack graphs are saved with this prefix for easy identification.

**Options:**

* `-h`, `--help`: Show the help message and exit.
* `-t`: Time window in which duplicate alerts are discarded (default: *1.0* sec).
* `-w`: Aggregate alerts occuring in this window as one episode (default: *150* sec).
* `--timerange`: A floating-point tuple limiting the alerts that are parsed and involved in the final attack graphs (default: *(0, 100)*).
> If not provided, the default values of (0,100) are used, meaning alerts from 0-th to 100-th hour (relative to the start of the alert capture) are parsed.
* `--dataset`: The name of the dataset with the alerts (default: *other*, available options: *cptc*, *other*).
> Since the IP addresses of the attackers are known for the CPTC dataset, irrelevant alerts are filtered out.
* `--keep-files`: Do not delete the .dot files after the program ends.
> By default, the generated dot files with the attack graphs are deleted. They might, however, be useful for analytics or testing.

**Examples:**

* Run SAGE with the default parameters on the CPTC-2017 dataset: `python sage.py alerts/cptc-2017/ exp-2017 --dataset cptc`
* Run SAGE with the time window of 2.0 seconds and the alert aggregation window of 200 seconds on the CPTC-2018 dataset: `python sage.py alerts/cptc-2018/ exp-2018 -t 2.0 -w 200 --dataset cptc`
* Run SAGE on the CCDC dataset and do not delete the dot files (you can omit `--dataset other`): `python sage.py alerts/ccdc/ exp-ccdc --dataset other --keep-files`

Tip: in case you often use the same non-default values, you can create an alias (e.g `alias sage="python sage.py -t 1.5 --dataset cptc --keep-files"` and then run `sage alerts/cptc-2017/ exp-2017`)

### First time use

- The FlexFringe binary and config are already in place at `FlexFringe/flexfringe`
  and `FlexFringe/ini/spdfa-config.ini`. You only need to rebuild FlexFringe
  from [source](https://github.com/tudelft-cda-lab/FlexFringe) if the committed
  binary is missing or incompatible with your machine — `./setup.sh` / `setup.ps1`
  do this automatically when needed.
- In case you move the `FlexFringe/` directory to another location, update the function `flexfringe` in `model_learning.py` accordingly.
- You can find the compressed alerts for the [Collegiate Penetration Testing Competition (CPTC)](https://cp.tc/research) and [Collegiate Cyber Defense Competition (CCDC)](https://github.com/FrankHassanabad/suricata-sample-data) datasets (taken from the linked sources) in the `alerts/` directory. If you haven't already decompressed them (see *Requires* above), you can add other datasets too, provided they follow the same format.
- You can run SAGE with the default parameters using the following command:

  `python sage.py alerts/ firstExp`,

  where `alerts/` contains the uncompressed alerts.
- NB! If you use the CPTC dataset, don't forget to add `--dataset cptc`, e.g.:

  `python sage.py alerts/ firstExp --dataset cptc`

- For other options, see Usage section above.

**If you use SAGE in a scientific work, consider citing the following papers:**

```
@inproceedings{nadeem2021sage,
  title={SAGE: Intrusion Alert-driven Attack Graph Extractor},
  author={Nadeem, Azqa and Verwer, Sicco and Yang, Shanchieh Jay},
  booktitle={Symposium on Visualization for Cyber Security (Vizec)},
  publisher={IEEE},
  year={2021}
}
```
```
@article{nadeem2021alert,
  title={Alert-driven Attack Graph Generation using S-PDFA},
  author={Nadeem, Azqa and Verwer, Sicco and Moskal, Stephen and Yang, Shanchieh Jay},
  journal={IEEE Transactions on Dependable and Secure Computing (TDSC)},
  year={2021},
  publisher={IEEE}
}
```
```
@inproceedings{nadeem2021enabling,
  title={Enabling visual analytics via alert-driven attack graphs},
  author={Nadeem, Azqa and Verwer, Sicco and Moskal, Stephen and Yang, Shanchieh Jay},
  booktitle={SIGSAC Conference on Computer and Communications Security (CCS)},
  year={2021},
  publisher={ACM}
}
```



#### Azqa Nadeem
#### TU Delft


