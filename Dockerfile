FROM node:18.9.0

RUN mkdir /code
COPY package* tsconfig* yarn.lock /code
COPY src /code/src
RUN cd /code && yarn install

WORKDIR /code
ENTRYPOINT ["yarn", "start"]