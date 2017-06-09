(function() {
  'use strict';
  
  let manager = null;
  
  async function getIdentities() {
    let readers;
    try {
      readers = await manager.listReaders();
    } catch (error) {
      console.log('Failed to list readers.');
      smartCard.logError(error);
      return [];
    }
    let identities = [];
    for (const reader of readers) {
      try {
        await manager.connect(reader);
      } catch (error) {
        console.log(`Failed to connect to reader ${reader}, skipping.`);
        smartCard.logError(error);
        continue;
      }
      let readerKeyBlob;
      let readerKeyId;
      try {
        await manager.selectApplet();
        readerKeyBlob = await manager.fetchPublicKeyBlobBase64();
        readerKeyId = await manager.fetchAuthenticationPublicKeyIdString();
      } catch (error) {
        console.log(
          `Failed to get public key ID from reader ${reader}, skipping.`);
        smartCard.logError(error);
        continue;
      } finally {
        await manager.disconnect();
      }
      identities.push({
        reader,
        readerKeyBlob,
        readerKeyId
      });
    }
    return identities;
  }
  
  function showIdentities(identities) { 
    if (identities.length > 0) {
      document.getElementsByClassName('identity-table-body')[0].innerHTML = '';
      document.getElementsByClassName('add-identity-message')[0].innerHTML =
       `Add one of the following SSH public keys to <span class="code">~/.ssh/authorized_keys</span> on the server:`;
      for (const identity of identities) {
        const identityRow = document.createElement('tr');
        const readerElement = document.createElement('td');
        readerElement.innerText = identity.reader;
        readerElement.title = identity.reader;
        const readerKeyIdElement = document.createElement('td');
        readerKeyIdElement.innerText = `${identity.readerKeyId.substring(0, 4)} ${identity.readerKeyId.substring(4)}`;
        const readerKeyBlobElement = document.createElement('td');
        readerKeyBlobElement.className = 'ssh-key';
        readerKeyBlobElement.dataset.head = 'ssh-rsa ' + identity.readerKeyBlob.substr(0, identity.readerKeyBlob.length - 30);
        readerKeyBlobElement.dataset.tail = identity.readerKeyBlob.substr(-30);
        readerKeyBlobElement.innerHTML = `<span class="nowrap">ssh-rsa </span>${identity.readerKeyBlob}`;
        readerKeyBlobElement.onclick = function(e) {
          const range = document.createRange();
          range.selectNodeContents(e.target);
          window.getSelection().removeAllRanges();
          window.getSelection().addRange(range);
        };
        identityRow.appendChild(readerElement);
        identityRow.appendChild(readerKeyIdElement);
        identityRow.appendChild(readerKeyBlobElement);
        document.getElementsByClassName('identity-table-body')[0].appendChild(identityRow);
      }
    } else {
      document.getElementsByClassName('identity-table-body')[0].innerHTML = '<tr></tr>';
      document.getElementsByClassName('add-identity-message')[0].textContent = 'Insert a smart card...';
    }
  }
  
  async function onReaderEvent() {
    const identities = await getIdentities();
    showIdentities(identities);
    manager.callOnReaderEvent(onReaderEvent);
  }
  
  window.onload = async function() {
    document.getElementsByClassName('relay-options')[0].value = `--ssh-agent=${chrome.runtime.id}`;
    document.getElementsByClassName('relay-options')[0].onclick = function(e) {
      e.target.select();
    };
    
    try {
      await smartCard.initializeApiContext();
      manager = new smartCard.OpenPGPSmartCardManager();
      await manager.establishContext();
    } catch (_) {
      document.getElementsByClassName('install-connector-step')[0].classList.remove('step-inapplicable');
      document.querySelectorAll('.install-connector-step ~ li')
              .forEach(el => el.classList.add('step-inapplicable'));
      return;
    }
    await onReaderEvent();
  };
  
})();