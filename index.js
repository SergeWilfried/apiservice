const express = require('express');
const app = express();
var jwt = require('express-jwt');
var jwks = require('jwks-rsa');
var morgan = require('morgan'); // Charge le middleware de logging
var session = require('cookie-session'); // Charge le middleware de sessions
var bodyParser = require('body-parser');
var axios = require('axios');

const port = process.env.PORT || 8080;

var bodyParser = require('body-parser');
var rp = require('request-promise');
const Firestore = require('@google-cloud/firestore');

const fs = require('fs')
const db = new Firestore();



var isAuthenticated = jwt({
    secret: jwks.expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: 'https://dev-1f5g1j38.eu.auth0.com/.well-known/jwks.json'
    }),
    audience: 'https://api.duniapay.net/',
    issuer: 'https://dev-1f5g1j38.eu.auth0.com/',
    algorithms: ['RS256']
});


app.use(morgan('combined'));
// Charge le middleware de gestion des paramètres
app.use(bodyParser.json());
//app.use(isAuthenticated);

app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header(
        "Access-Control-Allow-Headers",
        "Origin, X-Requested-With, Content-Type, Accept, Authorization"
    );
    if (req.method === 'OPTIONS') {
        res.header('Access-Control-Allow-Methods', 'POST, PATCH, GET');
        return res.status(203).json({});
    }
    next();
})


//request auth token
app.post('/register', (req, res) => {
    let user = req.body
    console.log('user ', user)
    let apiKey = req.headers['x-api-key']
    console.log('headers ', req.headers)
    console.log('apikey exist ', apiKey)
    if (req.headers['user-agent'] == 'GoogleStackdriverMonitoring-UptimeChecks(https://cloud.google.com/monitoring)') {
        console.info('health check passsed')
        res.send(200)
    }
    let endpointFeed = 'https://dev-1f5g1j38.eu.auth0.com/oauth/token'
    let requestConfig = {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{"client_id":"7tK31oPWaKGR3tvQoZ6k1XRaWLdKTBlW","client_secret":"v-ugp3gHl7GUueev7nUnVu_Ex8KFThhmvODBLLAFckOb5MiXQ8nndf7L_xrUIVPn","audience":"https://api.duniapay.net/","grant_type":"client_credentials"}'
    };
    if (user === undefined) return
    let setBj = db.collection('partners').doc(user.id).set(user).then(onValue => {
        if (onValue) {
            console.log('No such document!', onValue);
        } else {
            console.log('Document data:', doc.data());
        }
    })
        .catch(err => {
            console.log('Error getting document', err);
        });

    rp(endpointFeed, requestConfig)
        .then((response) => {
            console.log(response)
            slackWorkflow(`Nouveau token crée`)
            res.status(200).json(response)
        }).catch((err) => {
            console.log('error', err)
            slackWorkflow(`:warning: Impossible d'authentifié le partenaire`)
            res.status(404).json(err)
        });
})




//request auth token
app.get('/auth', (req, res) => {
    console.log('body ', req.body)
    let apiKey = req.headers['x-api-key']
    console.log('headers ', req.headers)
    console.log('apikey exist ', apiKey)
    if (req.headers['user-agent'] == 'GoogleStackdriverMonitoring-UptimeChecks(https://cloud.google.com/monitoring)') {
        console.info('health check passsed')
        res.send(200)
    }
    let endpointFeed = 'https://dev-1f5g1j38.eu.auth0.com/oauth/token'
    let requestConfig = {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{"client_id":"7tK31oPWaKGR3tvQoZ6k1XRaWLdKTBlW","client_secret":"v-ugp3gHl7GUueev7nUnVu_Ex8KFThhmvODBLLAFckOb5MiXQ8nndf7L_xrUIVPn","audience":"https://api.duniapay.net/","grant_type":"client_credentials"}'
    };
    rp(endpointFeed, requestConfig)
        .then((response) => {
            console.log(response)
            slackWorkflow(`Nouveau token crée`)
            res.status(200).json(response)
        }).catch((err) => {
            console.log('error', err)
            slackWorkflow(`:warning: Impossible d'authentifié le partenaire`)
            res.status(404).json(err)
        });
})






app.post('/payments/mass/send', isAuthenticated, (req, res) => {
    let requestBody = req.body
    //console.log('requestBody ', requestBody)
    let transactions = requestBody
    let apiKey = req.headers['x-api-key']
    let env = req.headers['environment']

    console.log('api key ', apiKey)
    let tx = []
    if (req.headers['user-agent'] == 'GoogleStackdriverMonitoring-UptimeChecks(https://cloud.google.com/monitoring)') {
        console.info('health check passsed')
        res.send(200)
    }
    for (i = 0; i < transactions.length; i++) {
        console.log('loop started')
        tx.push({
            "tx_type": "debit",
            "subtype": "mass_send",
            "user": transactions[i].partner_secret_key,
            "amount": transactions[i].amount_received,
            "account": transactions[i].partner_accountRef,
            "currency": "DEMO",
            "metadata": {
                "partnerTxId": transactions[i].partner_transaction_Id,
                "transaction_provider_mode": transactions[i].transaction_provider_mode,
                "transaction_provider_name": transactions[i].transaction_provider_name
            }
        },
            {
                "tx_type": "credit",
                "subtype": "mass_send",
                "user": transactions[i].recipient_mobile,
                "amount": transactions[i].amount_received,
                "account": transactions[i].recipient_account_ref,
                "currency": "DEMO",
                "metadata": {
                    "partnerTxId": transactions[i].partner_transaction_Id,
                    "transaction_provider_mode": transactions[i].transaction_provider_mode,
                    "transaction_provider_name": transactions[i].transaction_provider_name
                }
            }
        )
        console.log('Transaction added ', tx[i])

    }

    console.log('formatted transaction list ', tx)

    let requestToken = 'Token ' + apiKey.toString()
    let endpointFeed = "https://api.rehive.com/3/admin/transactions/"
    let requestConfig = {
        method: 'POST',
        json: true,
        body: {
            "transactions": tx
        },
        resolveWithFullResponse: false,
        headers: {
            'Content-Type': 'application/json',
            'Authorization': requestToken,
        },
    }
    console.log('Token ', apiKey)

    rp(endpointFeed, requestConfig)
        .then((response) => {
            res.json({
                "status": response.status,
                "transaction status": response.data.status
            })
        }).catch((err) => {
            if (err.statusCode == 400) {
                res.status(403).json({
                    "name": err.error.status,
                    "statusCode": err.statusCode,
                    "message": "Mass send are disabled for this account"
                });
            }
            res.status(400).json({
                "name": err.error.status,
                "statusCode": err.statusCode,
                "message": err.message.replace('\\', '')
            });
        });
})



app.post('/payments/send', isAuthenticated, (req, res) => {
    let requestBody = req.body
    let apiKey = req.headers['x-api-key']
    let env = req.headers['environment']
    var partnersRef = db.collection("partners");
    var partnerAccount;
    let currency = req.body.recipient_local_currency
    console.info('currency from payload', req.body.recipient_local_currency)
    try {
        partnersRef.where("x-api-key", "==", apiKey)
            .get()
            .then(function (querySnapshot) {
                querySnapshot.forEach(function (doc) {
                    // doc.data() is never undefined for query doc snapshots

                    partnerAccount = doc.data()
                    console.info('partnerAccount', partnerAccount)
                    let userBalance = partnerAccount['accounts'][currency]['balance'];
                    if (Number(userBalance < Number(req.body.amount_received))) {
                        res.status(403).json({
                            'status': 'Failure',
                            'message': 'Insufficient balance',
                        })
                    }
                });
            })
            .catch(function (error) {
                console.error("Unable to access this partner account ", error);
                res.status(404).json({
                    'status': 'Failed',
                    'message': 'Unauthorized access. Please contact your account manager'
                })
            });
    } catch (error) {
        console.error(error)
        res.status(404).json({
            'status': 'Failed',
            'message': 'Unauthorized access. Please contact your account manager'
        })
    }

    let tx = [
        {
            "tx_type": "debit",
            "user": "a604bc93-febd-43ff-9398-8bc8dbe0c64e",
            "amount": req.body.amount_received,
            "account": req.body.partner_accountRef,
            "subtype": 'payout',
            "currency": 'DEMO',
            "metadata": {
                "partnerTxId": req.body.partner_transaction_Id,
                "transaction_provider_mode": req.body.transaction_provider_mode,
                "transaction_provider_name": req.body.transaction_provider_name
            }
        },
        {
            "tx_type": "credit",
            "subtype": "payout",
            "user": req.body.recipient_mobile,
            "amount": req.body.amount_received,
            "account": req.body.recipient_account_ref,
            "currency": "TOKEN",
            "metadata": {
                "partnerTxId": req.body.partner_transaction_Id,
                "transaction_provider_mode": req.body.transaction_provider_mode,
                "transaction_provider_name": req.body.transaction_provider_name
            }
        }
    ]

    if (req.headers['user-agent'] == 'GoogleStackdriverMonitoring-UptimeChecks(https://cloud.google.com/monitoring)') {
        console.info('health check passsed')
        res.send(200)
    }
    let requestToken = 'Token ' + apiKey.toString()
    //  console.log(requestHeader)
    let endpointFeed = "https://api.rehive.com/3/admin/transactions/"
    let requestConfig = {
        method: 'POST',
        json: true,
        body: {
            "transactions": tx
        },
        resolveWithFullResponse: false,
        headers: {
            'Content-Type': 'application/json',
            'Authorization': requestToken,
        },
    }
    console.log('Token ', apiKey)
    if (env == "sandbox") {
        /// Initiate batch update
        var batch = db.batch();
        /// Update balance
        batch.update(partnerAccount, {
            "accounts": {
                'XOF': {
                    'balance': Number(userBalance) - Number(req.body.amount_received)
                }
            }
        });
    } else {
        rp(endpointFeed, requestConfig)
            .then((response) => {
                let payload = {
                    "status": response.status,
                    "transaction status": response.data.status
                }
                batch.update(partnerAccount, {
                    "status": payload
                })
                batch.commit();
                res.status(200).json(payload)
            }).catch((err) => {
                let payload = {
                    "name": err.error.status,
                    "statusCode": err.statusCode,
                    "message": err.message.replace('\\', '')
                }
                batch.commit();
                batch.update(partnerAccount, {
                    "status": payload
                })
                res.status(400).json(payload);
            });
    }
    res.end()
})


app.post('/payments/request', isAuthenticated, async (req, res) => {
    let requestBody = req.body
    let apiKey = req.headers['x-api-key']
    let env = req.headers['environment']

    if (env == 'sandbox') {
        if (requestBody.customer_otp_code == "546123") {
            await sendPayment('ORANGE', 200, '56525141', 'SERGE KIEMA', 5).then((onValue) => {
                res.status(200).json(onValue).catch((onError) => {
                    res.status(404).json(onError)
                })
            })

        } else {
            res.status(400).json({
                "statusCode": 400,
                "message": 'OTP invalide'
            });
        }
    }
    else {

        let tx = [
            {
                "tx_type": "debit",
                "user": req.body.customer_email,
                "amount": req.body.amount_paid,
                "subtype": 'charge',
                "currency": "DEMO",
                "metadata": {
                    // "otp": req.body.tx_otp,
                    "partnerTxId": req.body.partner_transaction_Id,
                    "transaction_provider_mode": req.body.transaction_provider_mode,
                    "transaction_provider_name": req.body.transaction_provider_name
                }
            },
            {
                "tx_type": "credit",
                "user": req.body.partner_secret_key,
                "amount": req.body.amount_paid,
                "account": req.body.partner_accountRef,
                "subtype": 'charge',
                "currency": req.body.recipient_local_currency,
                "metadata": {
                    "partnerTxId": req.body.partner_transaction_Id,
                    "transaction_provider_mode": req.body.transaction_provider_mode,
                    "transaction_provider_name": req.body.transaction_provider_name
                }
            },
        ]

        let requestToken = 'Token ' + apiKey.toString()
        let endpointFeed = "https://api.rehive.com/3/admin/transactions/"
        let requestConfig = {
            method: 'POST',
            json: true,
            body: {
                "transactions": tx
            },
            resolveWithFullResponse: false,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': requestToken,
            },
        }

        rp(endpointFeed, requestConfig)
            .then((response) => {
                res.json({
                    "status": response.status,
                    "transaction status": response.data.status
                })
            }).catch((err) => {
                console.log(req.body.amount_paid)
                res.status(400).json({
                    "name": err.error.status,
                    "statusCode": err.statusCode,
                    "message": err.message.replace('\\', '')
                });
            });
    }
})


app.post('/accounts/customer/update', isAuthenticated, (req, res) => {
    let requestBody = req.body
    let apiKey = req.headers['x-api-key']
    if (req.headers['user-agent'] == 'GoogleStackdriverMonitoring-UptimeChecks(https://cloud.google.com/monitoring)') {
        console.info('health check passsed')
        res.send(200)
    }
    let requestToken = 'Token ' + apiKey.toString()
    let userId = req.body.userId;

    console.log('update user ', userId)
    let email = req.body.customer_email
    let mobile = req.body.customer_mobile;
    var _updates;
    var _changes = 'email';
    if (email == undefined && mobile == undefined) return
    if (email == undefined) {
        _updates = mobile;
        _changes = 'mobile'
    }
    let endpointFeed = "https://api.rehive.com/3/admin/users/" + userId + "/"
    let requestConfig = {
        method: 'PATCH',
        json: true,
        resolveWithFullResponse: false,
        headers: {
            'Content-Type': 'application/json',
            'Authorization': requestToken,
        },
        body: {
            _changes: _updates
        }
    }

    rp(endpointFeed, requestConfig)
        .then((response) => {
            res.json({
                "status": response.status,
            })
        }).catch((err) => {
            res.status(400).json({
                "name": err.error.status,
                "statusCode": err.statusCode,
                "message": err.message.replace('\\', '')
            });
        });
})


app.get('/accounts/customer:txId', isAuthenticated, (req, res) => {
    let requestBody = req.body
    let apiKey = req.headers['x-api-key']

    let requestToken = 'Token ' + apiKey.toString()
    let userId = req.params.txId.replace(':', '')
    console.log('hola ', userId)

    if (req.headers['user-agent'] == 'GoogleStackdriverMonitoring-UptimeChecks(https://cloud.google.com/monitoring)') {
        console.info('health check passsed')
        res.send(200)
    }

    let endpointFeed = "https://api.rehive.com/3/admin/users/" + userId + "/"
    let requestConfig = {
        method: 'GET',
        json: true,
        resolveWithFullResponse: false,
        headers: {
            'Content-Type': 'application/json',
            'Authorization': requestToken,
        },
    }

    rp(endpointFeed, requestConfig)
        .then((response) => {
            res.json({
                "status": response.status,
                "first_name": response.data.first_name,
                "last_name": response.data.last_name,
                "email": response.data.email,
                "mobile": response.data.mobile
            })
        }).catch((err) => {
            res.status(400).json({
                "name": err.error.status,
                "statusCode": err.statusCode,
                "message": err.message.replace('\\', '')
            });
        });
})


app.get('/accounts/customer/delete:txId', isAuthenticated, (req, res) => {
    res.status(200).json({
        "status": 'Successfull',
        "statusCode": 200,
        "message": 'This endpoint will be depreceated by March 5th 2020'
    });
})


app.post('/accounts/customer/create', (req, res) => {
    let requestBody = req.body
    let apiKey = req.headers['x-api-key']

    let requestToken = 'Token ' + apiKey.toString()

    if (req.headers['user-agent'] == 'GoogleStackdriverMonitoring-UptimeChecks(https://cloud.google.com/monitoring)') {
        console.info('health check passsed')
        res.send(200)
    }

    // payload variables
    let first_name = req.body.customer_firstName;
    let last_name = req.body.customer_lastName;
    let email = req.body.customer_email;
    let mobile = req.body.customer_mobile;

    console.info(`firstname `, first_name)
    console.info(`last_name `, last_name)
    console.info(`email `, email)
    console.info(`mobile `, mobile)


    let endpointFeed = "https://api.rehive.com/3/admin/users/"
    let requestConfig = {
        method: 'POST',
        json: true,
        resolveWithFullResponse: false,
        headers: {
            'Content-Type': 'application/json',
            'Authorization': requestToken,
        },
        body: {
            "first_name": first_name,
            "last_name": last_name,
            "mobile": mobile,
            "email": email,
        }
    }

    rp(endpointFeed, requestConfig)
        .then((response) => {
            res.json({
                "status": response.status,
                "userId": response.data.id
            })
        }).catch((err) => {
            res.status(400).json({
                "name": err.error.status,
                "statusCode": err.statusCode,
                "message": err.message.replace('\\', '')
            });
        });
})




app.get('/payments/resolve:txId', isAuthenticated, (req, res) => {
    let requestBody = req.body
    let apiKey = req.headers['x-api-key']

    let requestToken = 'Token ' + apiKey.toString()
    let transactionId = req.params.txId.replace(':', '')
    console.log('hola ', transactionId)
    if (req.headers['user-agent'] == 'GoogleStackdriverMonitoring-UptimeChecks(https://cloud.google.com/monitoring)') {
        console.info('health check passsed')
        res.send(200)
    }
    let endpointFeed = "https://api.rehive.com/3/admin/transactions/" + transactionId + "/"
    let requestConfig = {
        method: 'GET',
        json: true,
        resolveWithFullResponse: false,
        headers: {
            'Content-Type': 'application/json',
            'Authorization': requestToken,
        },
    }

    rp(endpointFeed, requestConfig)
        .then((response) => {
            res.json({
                "status": response.status,
                "transaction status": response.data.status
            })
        }).catch((err) => {
            res.status(400).json({
                "name": err.error.status,
                "statusCode": err.statusCode,
                "message": err.message.replace('\\', '')
            });
        });
})



app.get('/accounts', isAuthenticated, (req, res) => {
    let requestBody = req.body
    let apiKey = req.headers['x-api-key']
    let requestToken = 'Token ' + apiKey.toString()
    let tx = {
        "active": true,
    }
    if (req.headers['user-agent'] == 'GoogleStackdriverMonitoring-UptimeChecks(https://cloud.google.com/monitoring)') {
        console.info('health check passsed')
        res.send(200)
    }

    let endpointFeed = "https://api.rehive.com/3/admin/accounts/" + requestBody.accountRef + "/"
    let requestConfig = {
        method: 'GET',
        json: true,
        resolveWithFullResponse: false,
        headers: {
            'Content-Type': 'application/json',
            'Authorization': requestToken,
        },
    }
    rp(endpointFeed, requestConfig)
        .then((response) => {
            console.log(response.data.currencies)
            res.status(200).json(response.data.currencies)
        }).catch((err) => {
            res.status(400).json({
                "name": err.error,
                "statusCode": err.statusCode,
                "message": err.message.replace('\\', '')
            });
        });
})


//check charge status
app.get('/status', (req, res) => {
    res.status(200).json('Up and Running !')
})



app.get('/', (req, res) => {
    console.log('awaiting paiements ...');
    const target = process.env.TARGET || ' ';
    res.send(`Welcome to ${target}!`);
});



app.listen(port, () => {
    console.log('Hello world listening on port', port);
});


async function slackWorkflow(message, channel) {
    const { IncomingWebhook } = require('@slack/webhook');
    const url = 'https://hooks.slack.com/services/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';
    const webhook = new IncomingWebhook(url);
    return webhook.send({
        text: message
    });
}




async function sendPayment(provider, amount, mobile, recipientName, charge) {
    var data = {
        "data": {
            "provider": provider,
            "operation": "CASHIN",
            "amount": amount,
            "mobile": mobile,
            "recipientName": recipientName,
            "charge": charge,
            "clientTimestamp": Date.now()
        },
    }
    await axios.post(`https://us-central1-duniapay-dc166.cloudfunctions.net/toMobileMoney`, data)
        .then(response => {
            // JSON responses are automatically parsed.
            console.info('SendPayment')

            console.info(response)
        })
        .catch(e => {
            this.errors.push(e)
            console.error('Payment Failure')

        })
}

async function requestPayment(provider, amount, mobile, otp, recipientName, charge) {
    var data = {
        "data": {
            "provider": provider,
            "operation": "CASHIN",
            "amount": amount,
            "mobile": mobile,
            "otp": otp,
            "recipientName": recipientName,
            "charge": charge,
            "clientTimestamp": Date.now()
        },
    }
    await axios.post(`https://us-central1-duniapay-dc166.cloudfunctions.net/postIntouch`)
        .then(response => {
            // JSON responses are automatically parsed.
            this.posts = response.data
        })
        .catch(e => {
            this.errors.push(e)
        })
}


