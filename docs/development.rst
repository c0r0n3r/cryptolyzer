-----------
Development
-----------

If you want to setup a development environment, you are in need of `uv <https://docs.astral.sh/uv/>`__.

.. code:: shell

   git clone --recurse-submodules \
   https://gitlab.com/coroner/cryptolyzer
   cd cryptolyzer
   uv sync --extra tests
   uv run --env-file .env cryptolyze -h
