-----------
Development
-----------

If you want to setup a development environment, you are in need of `pipenv <https://docs.pipenv.org/>`__.

.. code:: shell

   git clone --recurse-submodules \
   https://gitlab.com/coroner/cryptolyzer
   cd cryptolyzer
   pipenv install --dev
   pipenv run python setup.py develop
   pipenv shell
   cryptolyze -h
