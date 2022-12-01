FROM protocolplatform/protocolplatform
# Metadata
LABEL version="1.0" \
      description="The Tamarin prover for security protocol verification - Sapic+ with concatenation" \
      org.opencontainers.image.authors="Anonymous"
# install runtime dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get -y --no-install-recommends install \
    	    bc vim htop git parallel
#         maude \
#         graphviz
# RUN apt-get -y --no-install-recommends install \
#     locales
# RUN sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && locale-gen
# ENV LANG en_US.UTF-8
# ENV LANGUAGE en_US:en
# ENV LC_ALL en_US.UTF-8
# RUN apt-get -y --no-install-recommends install \
#     python3
# RUN apt-get -y --no-install-recommends install \
#     python
USER root
COPY Docker/res/entrypoint.sh /usr/local/bin/
COPY Docker/res/time /usr/local/bin/

RUN chmod 755 /usr/local/bin/entrypoint.sh

RUN mkdir -p /opt/lake-edhoc
WORKDIR /opt/lake-edhoc

EXPOSE 3001
COPY . .
RUN rm -f README
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
## docker run -it protocolanalysis/lake-edhoc:draft-14 bash
