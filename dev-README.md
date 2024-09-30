# Package Development 

## Pyenv - https://github.com/pyenv/pyenv
`pyenv` helps to manage different Python installations side by side.

<span class="notes">**Note:** Currently, not in use.</span>

Example:
```shell
$ pyenv install 3.11.0
$ pyenv install 3.10.0
$ pyenv install 3.9.0
$ pyenv install 3.8.0
$ pyenv local 3.11.0 3.10.0 3.9.0 3.8.0
$ python --version
Python 3.8.0
```
## Editable distribution

For development it is preferable to install `manifest-tool` package in
"editable mode" (a.k.a "developer mode") by:
```shell
$ pip install -editable .
```

## dev_init.sh

A helper script for bootstrapping development environment.

Usage:
```shell
$ source dev_init.sh
$ manifest-dev-tool --version
Manifest-Tool version 2.0
```

## dev_init.bat

Same as `dev_init.sh` but for Windows

## pytest

- execute `pytest` command to verify no regression was introduced.
`pytest` will also generate `htmlcov/index.html` that can be opened in a browser for showing test coverage statistics.

- Example of running only one test:
  ```
  pytest tests/dev_tool/test_dev_update.py -o log_cli=true -k test_cli_update_happy_day[fw_file-True-action0]
  ```

## tox

`tox` is an automation tool. Details can be found here:
https://tox.readthedocs.io/en/latest/  
`tox` helps to automate testing on different python versions.

Execute: `tox` command to test all supported Python environments.  
Execute `tox -e py38` to test only the python3.8 environment.

## wheel creation

```shell
$ pyenv local 3.9.0
$ python setup.py bdist_wheel
$ pyenv local 3.8.9
$ python setup.py bdist_wheel
```
do the same on each platform (Windows, Linux, macOS) per Python
interpreter.

The resulting wheel packages will be found under `dist` directory.

> Note: all the packages are created automatically by running `tox`
> command.

## sdist

Source distribution - can be done once as it is platform and Python
version agnostic.

```shell
python setup.py sdist
```
the resulting archive (`tar.gz`) will be found under `dist` directory

> Note: all the packages are created automatically by running `tox`
> command.

## manylinux wheels
PyPi does not allow uploading platform-specific wheels. More details can be 
found here: [PEP-0513](https://www.python.org/dev/peps/pep-0513/#rationale).  

To create [manylinux](https://github.com/pypa/manylinux) wheel files
execute the following script: `./build_manylinux_wheels.sh`.  
> Note: this will require the `docker` command. Make sure you have installed docker.

## Dependent packages versions
Dependent package versions should be tested with both lower and higher
bounds. Tox tests with new virtual env where all the latest versions will
be installed.  
When issuing a new release:
- test lower bound versions - if they are still applicable to latest
  changes.
- bump the higher bound versions and test against them.

We must freeze upper-bound versions to the version which were tested at
the release creation time.

## Publish release
1. In the `manifest-tool-internal` repository:
   1. Update `requirements.txt` to dependencies latest version.
   1. Bump the package [version](./manifesttool/__init__.py) and tar name in [tox.ini](./tox.ini).
   1. Create a PR with the above changes and merge it to the master branch.
   1. Check that the `PR-checker` workflow passes on the master branch. It runs all the tox tests on all the OSes.
   1. Check that the `create-Linux-wheels` workflow passes on the master branch. It builds the Linux wheels.
1. Compare manually between the `manifest-tool-internal` repo and the `manifest-tool` repo. Copy the required changes to the `manifest-tool` repo.
1. In the `manifest-tool` repository:
   1. Create a PR with the changes to master. Merge it after successful PR checks and approval.
   1. Check that the `PR-checker` workflow passes on the master branch. It runs all the tox tests on all the OSes.
   1. Check that the `create-Linux-wheels` workflow passes on the master branch. It builds the Linux wheels and uploads them as an artifact.
   1. Download the `wheels-manylinux.zip` and `wheels-tar-gz.zip `artifacts to your local machine from the `create-Linux-wheels` workflow.
   1. Extract both zip files to a `<dist-folder>` folder.
   1. Install `twine`: `pip install twine`.
   1. Publish to https://test.pypi.org and check:
      ```
      twine upload -r testpypi <dist-folder>/*
      ```
   1. Publish to https://pypi.org:
      ```
      twine upload <dist-folder>/*
      ```
1. Yank older pre-releases in https://pypi.org/manage/project/manifest-tool/releases/
1. Close fixed issues
1. Create a tag and a release in `manifest-tool-internal` and `manifest-tool` repos.
