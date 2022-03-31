from setuptools import setup, find_packages


with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='nat-server',
    version='0.1.0',
    description='DSU CSC-841 Lab 08 and 09',
    long_description=readme,
    author='Michael MacFadden',
    author_email='michael@macfadden.org',
    url='https://github.com/mmacfadden/csc-841-lab-8-and-9',
    license=license,
    packages=find_packages(exclude=('docs'))
)