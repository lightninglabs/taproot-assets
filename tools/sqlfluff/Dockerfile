FROM sqlfluff/sqlfluff:latest

COPY sqlfluff_plugin_ref_type/ /plugins/sqlfluff_plugin_ref_type/

ENV PYTHONPATH="/plugins/sqlfluff_plugin_ref_type"

USER root

RUN cd /plugins/sqlfluff_plugin_ref_type \
    chown -R 5000 . \
    && chmod -R 777 /plugins /sql \
    && pip install -e .

USER 5000
