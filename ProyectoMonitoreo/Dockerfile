FROM python:3.6

RUN mkdir /dependencias

COPY requeriments.txt /dependencias

RUN pip3 install -r /dependencias/requeriments.txt

ENV SECRET_KEY=""
ENV DB_NAME=""
ENV DB_USER=""
ENV DB_PASSWORD=""
ENV DB_HOST=""
ENV DB_PORT=3306
ENV host=""
ENV user=""
ENV passwd=""
ENV database=""
ENV URL_SERVICIOS=""
ENV CLIENTE_SERVICIOS_USR=""
ENV CLIENTE_SERVICIOS_PWD=""
ENV ADMINSERV_ACTIVO=""
ENV MYSQL_ROOT_PASSWORD=""
ENV MYSQL_DATABASE=""

RUN mkdir /code
RUN mkdir /start

COPY ./run.sh /start
RUN chmod +x /start/run.sh

WORKDIR /code

CMD /start/run.sh

