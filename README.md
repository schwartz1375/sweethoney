# Sweethoney
Sweethoney is a file triaging tool.  The tool parses out the following information:

* PE header information
* Lists functions declared and referenced
* Lists exported symbols
* Calculates file statics
* Alerts on suspicious IAT - This is a static list, and it maybe need to be tuned for your use case!
* Alerts on suspicious sections with extremely low (less than 1) & high (greater than 7) entorpy

For golang binaries please look at the [Go Reverse Engineering Tool Kit](https://go-re.tk/)

# How to build the Docker image
docker build -t schwartz1375/sweethoney:latest -f ./Dockerfile .

or do 

```
$ docker pull schwartz1375/sweethoney
```

The most basic form is to run the container and use wget/curl to pull the file sample in and run sweethoney.

```
$ docker run -it --name=sweethoney schwartz1375/sweethoney
```