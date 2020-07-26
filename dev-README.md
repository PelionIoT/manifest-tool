# Package Development 

## Pyenv - https://github.com/pyenv/pyenv
`pyenv` helps to manage different Python installations side by side.

Example:
```shell
$ pyenv install 3.8.0
$ pyenv install 3.7.5
$ pyenv install 3.6.9
$ pyenv install 3.5.7
$ pyenv local 3.8.0 3.7.5 3.6.9 3.5.7
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

## pytest

execute `pytest` command to verify no regression was introduced.
`pytest` will also generate `htmlcov/index.html` that can be opened in a browser for showing test coverage statistics.

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

