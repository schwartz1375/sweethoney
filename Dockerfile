FROM ubuntu

LABEL maintainer="Matthew Schwartz @schwartz1375"

WORKDIR /root
USER root

RUN DEBIAN_FRONTEND=noninteractive \
        apt-get -y update && apt-get -y \
        dist-upgrade && apt-get clean && apt-get install -y \
        ca-certificates tmux vim wget curl \
        build-essential libffi-dev python3 python3-dev python3-pip libfuzzy-dev 

RUN pip3 install pefile python-magic termcolor ssdeep

RUN wget https://github.com/schwartz1375/sweethoney/raw/master/sweethoney.py
RUN chmod +x sweethoney.py

WORKDIR /root

CMD ["/bin/bash"]