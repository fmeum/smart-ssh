#!/usr/bin/env bash
bower install
python download-google-smart-card-client-library.py

rm -rf build
rm smart-ssh.zip

mkdir build
declare -a files=("agent.js"
                  "app.css"
                  "app.html"
                  "app.js"
                  "pinDialog.css"
                  "pinDialog.html"
                  "pinDialog.js"
                  "pinCache.js"
                  "smartCard.js"
                  "manifest.json"
                  "google-smart-card-client-library.js"
                  "smart-ssh_48.png"
                  "smart-ssh_128.png"
                  "bower_components/chrome-promise/chrome-promise.js"
                  "bower_components/openpgp/dist/openpgp.min.js"
                  "bower_components/material-design-icons/action/1x_web/ic_lock_open_black_24dp.png"
                  "bower_components/material-design-icons/communication/1x_web/ic_vpn_key_black_24dp.png"
                  "bower_components/material-design-icons/action/1x_web/ic_help_black_24dp.png"
                  "bower_components/material-design-icons/hardware/1x_web/ic_sim_card_black_24dp.png")

cp --parents "${files[@]}" build/
cp LICENSE.build build/LICENSE

cd build
zip -r ../smart-ssh.zip *
