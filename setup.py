from distutils.core import setup

setup(
    name='capellaApi',
    version='1.0',
    py_modules=[
        'CapellaAPI',
        'CapellaAPIRequests',
        'CapellaAPIAuth',
        'CapellaExceptions'
    ],
    install_requires=['requests']
)
