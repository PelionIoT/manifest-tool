# Package Development 

## Pyenv - https://github.com/pyenv/pyenv
`pyenv` helps to manage different Python installations side by side.

<span class="notes">**Note:** Currently, not in use.</span>

Example:
```shell
$ pyenv install 3.8.0
$ pyenv install 3.7.5
$ pyenv install 3.6.9
$ pyenv local 3.8.0 3.7.5 3.6.9
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
  pytest tests/dev_tool/test_dev_update.py -o log_cli=true -k test_cli_update_delta_happy_day[action0]
  ```

## tox

`tox` is an automation tool. Details can be found here:
https://tox.readthedocs.io/en/latest/  
`tox` helps to automate testing on different python versions.

Execute: `tox` command to test all supported Python environments.  
Execute `tox -e py38` to test only the python3.8 environment.

## wheel creation

```shell
$ pyenv local 3.7.5
$ python setup.py bdist_wheel
$ pyenv local 3.6.9
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
PyPi does not allows uploading platform-specific wheel. More details can be 
found here: [PEP-0513](https://www.python.org/dev/peps/pep-0513/#rationale).  

To create [manylinux](https://github.com/pypa/manylinux) wheel files
execute following script: `./build_manylinux_wheels.sh`.  
> Note: this will require `docker` command. Make sure you have installed docker.

## Dependent packages versions
Dependent packages version should be tested with both lower and higher
bound. Tox tests with new virtual env where all the latest versions will
be installed.  
When issuing a new release:
- test lower bound versions - if they are still applicable to latest
  changes.
- bump the higher bound versions and test against them.

We must freeze upper bound versions to the version which were tested at
the release creation time.

## Publish release
1. Update `requirements.txt` to dependencies latest version.
1. Bump the package [version](./manifesttool/__init__.py) and tar name in [tox.ini](./tox.ini).
1. Run `tox` on Windows, Linux and Mac.
1. Create release on GitHub.
1. Run `build_manylinux_wheels.sh` on Linux.
1. Gather wheels and tar.gz from all `dist` folder into one dist folder:
   ```
   scp $USER@<source base path>/manifest-tool/dist/*.whl dist/
   ```
1. Install `twine`: `pip install twine`.
1. Publish to https://test.pypi.org and check:
    ```
    twine upload -r testpypi dist/*
    ```
1. Publish to https://pypi.org:
    ```
    twine upload dist/*
    ```
1. Yank older pre-releases in https://pypi.org/manage/project/manifest-tool/releases/
1. Close fixed issues