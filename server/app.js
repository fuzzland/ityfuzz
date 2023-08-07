const express = require('express');
const axios = require('axios');
const process = require('process');

const app = express();
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf
  }
}))

let data = [];

let targetUrl = 'http://localhost:8545';

// Parse command line argument for target url
if (process.argv.length > 2) {
  targetUrl = process.argv[2];
}

// Add an endpoint to retrieve the collected data
app.get('/data', (req, res) => {
  res.send(data);
});

// Collect and analyze request and response
app.all('*', async (req, res) => {
  try {
    const { originalUrl, method, headers, query, cookies } = req;
    body = req.rawBody.toString();
    const response = await axios({
      method: method,
      url: `${targetUrl}${originalUrl}`,
      headers: headers,
      data: body,
      params: query,
    });
    console.log(`Request: ${method} ${originalUrl} ${body}`)
    console.log(`Response: ${response.status} ${JSON.stringify(response.data)}`);
    data.push({
      method: req.method,
      url: req.url,
      body: req.body,
      headers: req.headers,
      response: {
        status: response.status,
        data: response.data,
        headers: response.headers,
      }
    });
    res.set(response.headers).status(response.status).send(response.data)
  } catch (err) {
    console.error(err);
    res.status(500).send(err.toString());
  }
});



const port = process.env.PORT || 5001;

app.listen(port, () => console.log(`Server listening on port ${port}`));
