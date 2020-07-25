# Vosk speech recognition modules for Asterisk

This is an asterisk module for [Vosk API](https://github.com/alphacep/vosk-api) server:

https://github.com/alphacep/vosk-server

It is tested with latest asterisk git master, but should equally work
with other branches (13,16,17).  Just make sure you have latest branch
update since we need some fixes in res_http_websocket.

## Installation

1) First build the modules

```
./bootstrap
./configure --with-asterisk=<path_to_source>/asterisk --prefix=<path_to_install>
make
make install
```

2) Edit `modules.conf` to load modules

```
load = res_speech.so
load = res_http_websocket.so
load = res_speech_vosk.so
```

3) Edit dialplan in `extensions.conf`:

```
[internal]
exten = 1,1,Answer
same = n,Wait(1)
same = n,SpeechCreate
same = n,Set(SPEECH_ENGINE(language)=${CHANNEL(language)})
same = n,SpeechBackground(hello)
same = n,Verbose(0,Result was ${SPEECH_TEXT(0)})
```

4) Run docker

```
docker run -d -p 2700:2700 alphacep/kaldi-en:latest
```

5) Dial extension and check the result
