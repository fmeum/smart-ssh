const pinCache = (function() {
  'use strict';
  
  let pinCache = {};
  
  function clearCache() {
    pinCache = {};
  }
  
  function getPinCount() {
    let count = 0;
    for (const key in pinCache)
      count += pinCache[key].length;
    return count;
  }
  
  function putPin(key, reader, pin, registerOnDisconnectCallback) {
    if (!(key in pinCache))
      pinCache[key] = {};
    pinCache[key][reader] = pin;
    window.setTimeout(async function() {
      await smartCard.initializeApiContext();
      const manager = new smartCard.OpenPGPSmartCardManager();
      await manager.establishContext();
      await manager.callOnDisconnect(reader, function() {
        deletePin(key, reader);
        const pinCount = getPinCount();
        let message;
        if (pinCount === 1)
          message = `1 PIN still cached`;
        else if (pinCount > 1)
          message = `${pinCount} PINs still cached`;
        else
          message = `PIN cache has been cleared`;
        chrome.notifications.create(null, {
          type: 'basic',
          iconUrl: 'bower_components/material-design-icons/communication/1x_web/ic_vpn_key_black_24dp.png',
          title: 'Card removed',
          message
        });
        manager.releaseContext();
      });
    }, 1)
  }
  
  function getPin(key, reader) {
    if (key in pinCache) 
      if (reader in pinCache[key])
        return pinCache[key][reader];
    return null;
  }
  
  function deletePin(key, reader) {
    if (key in pinCache) {
      // Remove reader (or do nothing if not present)
      delete pinCache[key][reader];
      // Remove key if it has no other readers assigned
      if (Object.keys(pinCache[key]).length === 0)
        delete pinCache[key];
    }
  }
  
  chrome.idle.onStateChanged.addListener(function(state) {
    if (state === "locked")
      clearCache();
  });
  
  chrome.runtime.onSuspend.addListener(function() {
    console.log('pinCache unloaded');
  });
  
  return {
    putPin,
    getPin,
    deletePin
  };
})();