import os
from setuptools import setup, find_packages
from importlib.machinery import SourceFileLoader


module_name = 'jwt_rsa'

module = SourceFileLoader(
    module_name,
    os.path.join(module_name, '__init__.py')
).load_module()


def load_requirements(fname):
    """ load requirements from a pip requirements file """
    line_iter = (line.strip() for line in open(fname))
    return [line for line in line_iter if line and not line.startswith("#")]


setup(
    name='pyjwt-rsa',
    version=module.__version__,
    author=module.__author__,
    author_email=module.authors_email,
    license=module.__license__,
    description=module.package_info,
    long_description=open("README.rst").read(),
    platforms="all",
    classifiers=[
        'Intended Audience :: Developers',
        'Natural Language :: Russian',
        'Operating System :: MacOS',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
    ],
    packages=find_packages(exclude=['tests']),
    install_requires=load_requirements('requirements.txt'),
    extras_require={
        'develop': load_requirements('requirements.dev.txt'),
    },
    entry_points={
        'console_scripts': [
            'jwt-rsa-keygen = {}.keygen:main'.format(module_name),
            'jwt-rsa-verify = {}.verify:main'.format(module_name),
            'jwt-rsa-issue= {}.issue:main'.format(module_name),
        ]
    },
    python_requires=">=3.4.*, <4",
)
