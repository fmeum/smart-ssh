(function() {
  'use strict';
  
  function init() {
    document.getElementsByName('pinBox')[0].placeholder = `PIN (${data.triesRemaining} tries remaining)`;
    document.getElementsByName('pinBox')[0].select();
    
    document.getElementsByClassName('fingerprint-info')[0].textContent = 
      `${data.fingerprint.substring(0, 4)} ${data.fingerprint.substring(4)}`;
    document.getElementsByClassName('reader-info')[0].textContent = data.reader;
    document.getElementsByName('cachePinCheckbox')[0].onchange = function(e) {
      document.getElementsByName('pinBox')[0].select();
    };
    
    document.forms[0].onsubmit = function(e) { 
        e.preventDefault();
        data.resolvePromise(e.target.elements['pinBox'].value, 
          e.target.elements['cachePinCheckbox'].checked);
        window.close();
      };
  }
  
  window.onload = init;
})();