# Professor Layton: Curious Village HD Vita

<p align="center"><img src="./screenshots/game.png"></p>

This is a wrapper/port of <b>Professor Layton: Curious Village HD</b> for the *PS Vita*.

The port works by loading the official Android ARMv7 executables in memory, resolving its imports with native functions and patching it in order to properly run.
By doing so, it's basically as if we emulate a minimalist Android environment in which we run natively the executable as is.

## Changelog

### v1.1

- Reworked Livearea assets (Thanks to YogaBudiW).
- Added possibility to play the game in flipped portrait mode (Create a file named ux0:data/layton_curious/flip.txt) to enable it.
- Mitigated the issue for which videos started with way faster speed and no audio and freezed sometimes.

### v1.0.3

- Removed FuHEN logo.

### v1.0.2

- Fixed an issue causing some puzzles to have broken rendering in portrait mode.

### v1.0.1

- Fixed an issue causing rotated elements to be invisible.
- Fixed an issue causing game locking up in certain circumstances.

### v1.0

- Initial release.

## Note

- This port works only with versions of the game where an obb file was still used. It has been tested with v.1.0.1 and v.1.0.3.
- Very rarely, videos can freeze or lack audio. If that happens, restart the homebrew (sceAvPlayer bug). You'll still be able to skip the video as usual.

## Known Issues

- Post puzzle solution animation is a bit slow. (Likely cause of I/O overhead)

## Setup Instructions (For End Users)

In order to properly install the game, you'll have to follow these steps precisely:

- Install [kubridge](https://github.com/TheOfficialFloW/kubridge/releases/) and [FdFix](https://github.com/TheOfficialFloW/FdFix/releases/) by copying `kubridge.skprx` and `fd_fix.skprx` to your taiHEN plugins folder (usually `ux0:tai`) and adding two entries to your `config.txt` under `*KERNEL`:
  
```
  *KERNEL
  ux0:tai/kubridge.skprx
  ux0:tai/fd_fix.skprx
```

**Note** Don't install fd_fix.skprx if you're using rePatch plugin

- **Optional**: Install [PSVshell](https://github.com/Electry/PSVshell/releases) to overclock your device to 500Mhz.
- Install `libshacccg.suprx`, if you don't have it already, by following [this guide](https://samilops2.gitbook.io/vita-troubleshooting-guide/shader-compiler/extract-libshacccg.suprx).
- Obtain your copy of *Professor Layton: Curious Village HD* legally for Android in form of an `.apk` file and an obb. [You can get all the required files directly from your phone](https://stackoverflow.com/questions/11012976/how-do-i-get-the-apk-of-an-installed-app-without-root-access) or by using an apk extractor you can find in the play store.
- Open the apk with your zip explorer and extract the file `libll1.so` from the `lib/armeabi-v7a` folder to `ux0:data/layton_curious`. 
- Extract the folder `assets` inside `ux0:data/layton_curious`.
- Extract the `obb` file in `ux0:data/layton_curious/data` and rename the file `main.obb`.

## Build Instructions (For Developers)

In order to build the loader, you'll need a [vitasdk](https://github.com/vitasdk) build fully compiled with softfp usage.  
You can find a precompiled version here: https://github.com/vitasdk/buildscripts/actions/runs/1102643776.  
Additionally, you'll need these libraries to be compiled as well with `-mfloat-abi=softfp` added to their CFLAGS:

- [SoLoud](https://github.com/vitasdk/packages/blob/master/soloud/VITABUILD)

- [libmathneon](https://github.com/Rinnegatamante/math-neon)

  - ```bash
    make install
    ```

- [vitaShaRK](https://github.com/Rinnegatamante/vitaShaRK)

  - ```bash
    make install
    ```

- [kubridge](https://github.com/TheOfficialFloW/kubridge)

  - ```bash
    mkdir build && cd build
    cmake .. && make install
    ```

- [vitaGL](https://github.com/Rinnegatamante/vitaGL)

  - ````bash
    make SOFTFP_ABI=1 NO_DEBUG=1 HAVE_GLSL_SUPPORT=1 PHYCONT_ON_DEMAND=1 HAVE_UNFLIPPED_FBOS=1 install
    ````

After all these requirements are met, you can compile the loader with the following commands:

```bash
mkdir build && cd build
cmake .. && make
```

## Credits

- TheFloW for the original .so loader.
- withLogic for testing the homebrew.
- YogaBudiW for the Livearea assets.
