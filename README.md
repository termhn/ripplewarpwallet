# RippleWarpWallet

A ripple brain wallet generator that uses scrypt.

## How to Use

### Hosted Client Version

For basic use, navigate to https://termhn.github.io/ripplewarpwallet, which is the compiled, hosted version of the latest stable version in this GitHub repo. Deterministic (verifiable) builds are implemented, and it is automatically deployed and hosted on GitHub pages, so you can be sure that the code here is really the same code that is compiled and used on the web version. In order to do verify this yourself, see the How to Verify section below.

### NPM Library

Add to your dependencies with the usual

```
yarn add ripplewarpwallet
```

Then use like so:

```javascript
const warp = require('ripplewarpwallet');

const params = {
    passphrase : 'testpassword',
    salt : 'testsalt',
    progress_hook : progress_output => {/*do something*/}
};

function callback(result) {
  const address = res.address;
  const secret = res.secret;
  console.log("Address: " + address + " Secret: " + secret);
}

warp(params, callback);
```


### Build Client Yourself

In order to build RippleWarpWallet yourself, you'll first need to install [git](https://git-scm.com/) and [yarn](https://yarnpkg.com/en/).

#### Windows

1. Download and install [git](https://git-scm.com/)
2. Download and install [Node](https://nodejs.org/en/) (get the Latest version)
3. Download and install [yarn](https://yarnpkg.com/en/docs/install#windows-tab)
4. Open up the program you installed called Git Bash. You can do this by clicking the Windows icon in the bottom left and then typing Git Bash into the search bar.

Now, type the following into the window that opens, pressing enter or return after each line

```
git clone https://github.com/termhn/ripplewarpwallet
cd ripplewarpwallet
```

This downloads the latest version of the source code from this repository onto your system and then puts you in that folder. Next we will install all the dependencies using yarn. Type:

```
yarn install
```

This has installed all the dependencies necessary to build the final page. Now we need to delete the prebuilt version. Navigate to the `dist` folder and delete `warp_latest.html` and `warp_1.0.3_SHA256_{numbers here}.html` files and delete them. We can then build it using

```
yarn build
```

Now, the latest version should be installed at `dist/warp_1.0.3_SHA256_{numbers here}.html`. You can also access it by clicking on the symbolic link `dist/warp_latest.html`. To find this in Windows Explorer, navigate to `C:\Users\<Username>\ripplewarpwallet\dist` directory.

#### macOS

Coming soon, you can probably adapt the Windows instructions if you know what you're doing. If you want to do this and you aren't sure how, send me a message or issue and I'll walk you through the process.

#### Linux

Coming soon, you can probably adapt the Windows instructions if you know what you're doing. If you want to do this and you aren't sure how, send me a message or issue and I'll walk you through the process.

### How to Verify

In order to verify that the version available online is the same as what is generated directly by the source code in this repository, you can follow these steps:

1. Follow the instructions above for "Build Yourself" for your platform.
2. Open an online diffing tool. These will allow you to compare the differences between two different text files. I'll use https://text-compare.com/
3. Navigate to https://termhn.github.io/ripplewarpwallet
4. Right click the page and click View Source
5. Press Control-A then Control-C (or Command-A then Command-C on macOS) to copy the page source, then go and paste it into one side of the diff tool.
5. Open the `ripplewarpwallet/dist/warp_1.0.3_SHA256_{numbers}.html` file you built yourself earlier and repeat the same process of rightclick -> view source -> ctrl+A ctrl+C then paste it into the other side of the diff tool
6. Press compare. In theory, they will be identical. You've now verified that the hosted version is exactly the same as the version you built yourself from the source code. Because of the way images etc. are embedded directly into the html and not referenced as any outside files, by comparing just the one final built html file you can be certain there are really no changes.

## Development

Ripple uses yarn to manage its dependencies. Run
```sh
$ yarn install
```
to install the needed dependencies.

## Build

```sh
$ yarn build
```
to build once, or
```sh
$ yarn start
```
to watch for changes and re-build during development.
