FROM debian:unstable

RUN apt-get update
RUN apt-get install -y squid3

ADD squid.conf /etc/squid3/squid.conf
RUN squid3 -k parse -f /etc/squid3/squid.conf

CMD ["squid3", "-C", "-N", "-f", "/etc/squid3/squid.conf", "-d", "1"]
