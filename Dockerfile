FROM node:12

RUN mkdir /home/node/app \
 && chown node /home/node/app
USER node
WORKDIR /home/node/app

COPY package.json package-lock.json ./
RUN npm install

COPY *.js ./

ENTRYPOINT ["npm", "start"]
EXPOSE 8000/tcp
