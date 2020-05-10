#!/usr/bin/env python

# Read https://github.com/django-extensions/django-extensions/issues/92
# Read: http://setuptools.readthedocs.io/en/latest/setuptools.html
# Look for find_packages, packages, package_dir

from setuptools import setup, find_packages
import codecs

with codecs.open('README.md', 'r', 'utf-8') as fd:
    long_description = fd.read()

pkg_version = "0.0.2"

setup(
    name='exponot',
    version=pkg_version,
    description='Exposure Notification reference implementation',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author='Viet Le',
    author_email='vietlq85@gmail.com',
    url='https://github.com/vietlq/exponot',
    #install_requires=['requests'],
    packages=find_packages(),
    #scripts=['tools/exponot'],
    keywords=['covid-19 exposure notification contact-tracing'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ])
