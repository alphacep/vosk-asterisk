# Vosk speech recognition modules for Asterisk

This is an asterisk module for [Vosk API](https://github.com/alphacep/vosk-api) server:

https://github.com/alphacep/vosk-server

It is tested with latest asterisk git master, but should equally work
with other branches (13,16,17). 


## Installation

1) Make sure you have latest asterisk update

```
git clone https://github.com/asterisk/asterisk
....
```

2) First build the modules

```
./bootstrap
./configure --with-asterisk=<path_to_asterisk_source> --prefix=<path_to_install>
make
make install
```

for example:

```
./bootstrap
./configure --with-asterisk=/usr --prefix=/usr
make
make install
```

3) Edit `modules.conf` to load modules

```
load = res_speech.so
load = res_http_websocket.so
load = res_speech_vosk.so
```

4) Edit dialplan in `extensions.conf`:

```
[internal]
exten = 1,1,Answer
same = n,Wait(1)
same = n,SpeechCreate
same = n,SpeechBackground(hello)
same = n,Verbose(0,Result was ${SPEECH_TEXT(0)})
```

5) Run Vosk server with the Docker

```
docker run -d -p 2700:2700 alphacep/kaldi-en:latest
```

6) Dial extension and check the result
