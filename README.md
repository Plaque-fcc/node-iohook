# node-iohook
NodeJS global keyboard and mouse hooks powered by libuiohook.

# Requirements

- Windows: VS2015+
- MAC: Clang
- Linux: GCC

# Install

``
  npm install node-iohook
`` 

# How

```
const hook = require('node-iohook')


hook.on('keydown', function(msg){
    console.log(msg);
});


hook.start();

```

# Extra
``node-iohook`` work with last ``nodejs`` LTS as well as ``electron``
