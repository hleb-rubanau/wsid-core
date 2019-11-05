import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
     name='wsid',  
     version='0.0.2',
     scripts=[] ,
     author="Hleb Rubanau",
     author_email="contact@rubanau.com",
     description="Implementation of WSID authentication mechanism",
     long_description=long_description,
     long_description_content_type="text/markdown",
     url="https://github.com/hleb-rubanau/wsid-core",
     packages=['wsid'],
     install_requires=[
        'PyNaCl', 
        'cachetools',
     ],
     license="MIT",
     classifiers=[
         "Programming Language :: Python :: 3",
         "License :: OSI Approved :: MIT License",
         "Operating System :: OS Independent",
     ],
)

