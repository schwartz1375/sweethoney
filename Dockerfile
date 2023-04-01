FROM ubuntu

LABEL maintainer="Matthew Schwartz @schwartz1375"

WORKDIR /root
USER root

ENV DEBIAN_FRONTEND=noninteractive

#RUN DEBIAN_FRONTEND=noninteractive \
RUN apt-get -y update && apt-get -y \
        dist-upgrade && apt-get clean && apt-get install -y \
        ca-certificates tmux vim wget curl tar zip \
        git golang\
        build-essential libffi-dev python3 python3-dev python3-pip libfuzzy-dev  

RUN pip3 install pefile python-magic termcolor ssdeep sslyze

ADD https://raw.githubusercontent.com/schwartz1375/sweethoney/master/sweethoney.py /root

RUN chmod +x sweethoney.py

WORKDIR /root

CMD ["/bin/bash"]
