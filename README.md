# Vosk speech recognition modules for Asterisk

This is an asterisk module for [Vosk API](https://github.com/alphacep/vosk-api) server:

https://github.com/alphacep/vosk-server

It is tested with latest asterisk git master, but should probably work for earlier versions.

## Installation

1) First build the modules

```
./configure --with-asterisk=<path_to_source>/asterisk --prefix=<path_to_install>
make
make install
```

2) Edit `modules.conf` to load modules

```
load = res_speech.so
load = res_speech_vosk.so
load = res_http_websocket_fix.so
```

disable original `res_http_websocket` since it contains bugs

```
; load = res_http_websocket.so
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
