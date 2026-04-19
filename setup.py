#!/usr/bin/env python3
"""Setup script for the Ansible FreeBSD jail connection plugin."""

import os

from setuptools import setup

this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='ansible-jailexec',
    version='1.1.0',
    author='Christian Hofstede-Kuhn',
    author_email='christian@hofstede.it',
    description='Ansible connection plugin for FreeBSD jails via jexec over SSH',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/chofstede/ansible_jailexec',
    py_modules=['jailexec'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX :: BSD :: FreeBSD',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: System :: Systems Administration',
        'Framework :: Ansible',
    ],
    python_requires='>=3.9',
    install_requires=[
        'ansible-core>=2.14',
        'PyYAML>=5.1',
    ],
    extras_require={
        'test': [
            'pytest>=7.0',
            'pytest-cov>=4.0',
        ],
    },
    keywords='ansible freebsd jail jexec connection plugin ssh',
    project_urls={
        'Bug Reports': 'https://github.com/chofstede/ansible_jailexec/issues',
        'Source': 'https://github.com/chofstede/ansible_jailexec',
    },
    include_package_data=True,
    zip_safe=False,
)
