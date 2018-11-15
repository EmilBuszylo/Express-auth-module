var jwt = require('jsonwebtoken');

function verifyToken(req, res, next) {

    if (req.headers['x-access-token'] && req.headers['x-access-token'].startsWith('Bearer')) {
        const token = req.headers['x-access-token'].replace('Bearer ', '');
        jwt.verify(token, 'top_secret', function (err, decoded) {
            if (err) {
                return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });
            }

            req.userId = decoded.id;
            next();
        });
    } else {
        return res.status(403).send({ auth: false, message: 'No token provided.' });
    }
}

module.exports = verifyToken;
