
var axios = require('axios');




export async function sendPayment(provider, amount, mobile, recipientName, charge) {
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

export async function requestPayment(provider, amount, mobile, otp, recipientName, charge) {
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