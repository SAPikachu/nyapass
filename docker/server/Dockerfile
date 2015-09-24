FROM python:3.5

WORKDIR /opt/app

RUN apt-get update \
    && apt-get install -y curl --no-install-recommends \
    && curl -SL https://github.com/SAPikachu/nyapass/archive/master.tar.gz | tar xzv --strip-components=1 \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && apt-get autoclean

RUN pip3 install -r requirements.txt
RUN ./chnetworks-build.py
ADD config.json nyapass-server.crt nyapass-server.key /opt/app/

EXPOSE 443

CMD ["./nyapass-server.py"]
