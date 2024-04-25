#FROM docker-remotes.artifactory.prod.aws.cloud.ihf/amazonlinux:latest
FROM amazonlinux:latest
LABEL maintainer Gabriel Galeazzi (gabriel.galeazzi@itau-unibanco.com.br)

# Install apt dependencies
RUN yum install -y \
    gcc gcc-c++ freetype-devel yum-utils findutils openssl-devel \
    && yum update rpm -y \
    && rm - rf /var/cache/yum/*

RUN yum install python3 -y \
    && yum install python3-pip -y \
    && rm -rf /var/cache/yum/*

ENV PATH=$PATH:/root/.local/bin

WORKDIR /usr/src/app

COPY ./src/app.py ./
COPY ./src/create_wallet.py ./
COPY ./src/sign_transaction.py ./
COPY ./run.sh ./
COPY requirements.txt ./

RUN pip3 install -r /usr/src/app/requirements.txt
RUN chmod a+x /usr/src/app/run.sh

ARG REGION_ARG=sa-east-1
ENV REGION=$REGION_ARG

CMD ["./run.sh"]
