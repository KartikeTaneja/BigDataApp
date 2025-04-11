const express = require('express');
const bodyParser = require('body-parser');
const Ajv = require('ajv');
const addFormats = require('ajv-formats');
const crypto = require('crypto');
const { createClient } = require('redis');
const { OAuth2Client } = require('google-auth-library');
const jsonpatch = require('fast-json-patch');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const port = 3000;

// Load public key for RS256 validation
// In production, store these securely and use environment variables
const publicKey = fs.readFileSync(path.join(__dirname, 'public_key.pem'));

// Configure Google OAuth client
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const googleClient = new OAuth2Client(CLIENT_ID);

// Initialize Ajv with stricter settings
const ajv = new Ajv({ 
    allErrors: true,
    coerceTypes: false,
    verbose: true,
    strict: true
});
addFormats(ajv);

// Connect to Redis
const redisClient = createClient();
redisClient.on('error', (err) => console.error('Redis Connection Error:', err));
redisClient.connect().then(() => console.log("Connected to Redis"));

// JSON Schema for validation
const schema = {
    "type": "object",
    "properties": {
        "_org": { "type": "string", "format": "hostname" },
        "objectId": { "type": "string", "pattern": "^[a-zA-Z0-9-_]+$" },
        "objectType": { "type": "string", "enum": ["plan"] },
        "planType": { "type": "string", "enum": ["inNetwork", "outOfNetwork"] },
        "creationDate": { "type": "string", "format": "date" },
        "planCostShares": {
            "type": "object",
            "properties": {
                "deductible": { "type": "number", "minimum": 0 },
                "_org": { "type": "string", "format": "hostname" },
                "copay": { "type": "number", "minimum": 0 },
                "objectId": { "type": "string", "pattern": "^[a-zA-Z0-9-_]+$" },
                "objectType": { "type": "string", "enum": ["membercostshare"] }
            },
            "required": ["deductible", "_org", "copay", "objectId", "objectType"],
            "additionalProperties": false
        },
        "linkedPlanServices": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "_org": { "type": "string", "format": "hostname" },
                    "objectId": { "type": "string", "pattern": "^[a-zA-Z0-9-_]+$" },
                    "objectType": { "type": "string", "enum": ["planservice"] },
                    "linkedService": {
                        "type": "object",
                        "properties": {
                            "_org": { "type": "string", "format": "hostname" },
                            "objectId": { "type": "string", "pattern": "^[a-zA-Z0-9-_]+$" },
                            "objectType": { "type": "string", "enum": ["service"] },
                            "name": { "type": "string", "minLength": 1, "maxLength": 100 }
                        },
                        "required": ["_org", "objectId", "objectType", "name"],
                        "additionalProperties": false
                    },
                    "planserviceCostShares": {
                        "type": "object",
                        "properties": {
                            "deductible": { "type": "number", "minimum": 0 },
                            "_org": { "type": "string", "format": "hostname" },
                            "copay": { "type": "number", "minimum": 0 },
                            "objectId": { "type": "string", "pattern": "^[a-zA-Z0-9-_]+$" },
                            "objectType": { "type": "string", "enum": ["membercostshare"] }
                        },
                        "required": ["deductible", "_org", "copay", "objectId", "objectType"],
                        "additionalProperties": false
                    }
                },
                "required": ["_org", "objectId", "objectType", "linkedService", "planserviceCostShares"],
                "additionalProperties": false
            }
        }
    },
    "required": ["_org", "objectId", "objectType", "planType", "creationDate", "planCostShares", "linkedPlanServices"],
    "additionalProperties": false
};

// Type validation helper
const validateTypes = (data, path = '') => {
    const errors = [];
    
    const checkValue = (value, key, currentPath) => {
        const fullPath = currentPath ? `${currentPath}.${key}` : key;
        
        if (['deductible', 'copay'].includes(key)) {
            if (typeof value !== 'number') {
                errors.push({
                    path: fullPath,
                    expected: 'number',
                    received: typeof value,
                    value: value
                });
            }
        } else if (['_org', 'objectId', 'objectType', 'planType', 'name'].includes(key)) {
            if (typeof value !== 'string') {
                errors.push({
                    path: fullPath,
                    expected: 'string',
                    received: typeof value,
                    value: value
                });
            }
        }
        
        if (value && typeof value === 'object') {
            if (Array.isArray(value)) {
                value.forEach((item, index) => {
                    Object.entries(item).forEach(([k, v]) => {
                        checkValue(v, k, `${fullPath}[${index}]`);
                    });
                });
            } else {
                Object.entries(value).forEach(([k, v]) => {
                    checkValue(v, k, fullPath);
                });
            }
        }
    };
    
    Object.entries(data).forEach(([key, value]) => {
        checkValue(value, key, path);
    });
    
    return errors;
};

// JWT validation middleware
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            error: 'Unauthorized',
            message: 'Authentication token is required'
        });
    }

    try {
        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: CLIENT_ID
        });

        const payload = ticket.getPayload();
        req.user = {
            sub: payload.sub,
            email: payload.email,
            name: payload.name
        };
        return next(); 
    } catch (error) {
        console.error('Token verification failed:', error);
        if (error.name === 'TokenExpiredError') {
            return res.status(403).json({
                error: 'Forbidden',
                message: 'Authentication token has expired'
            });
        } else { 
            return res.status(403).json({
                error: 'Forbidden',
                message: 'Invalid authentication token' 
            });
        }
    }
};

// Error handler middleware
const errorHandler = (err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({
        error: 'Internal Server Error',
        message: err.message
    });
};

// Request validation middleware
const validateRequest = (req, res, next) => {
    // Skip validation for DELETE requests
    if (req.method === 'DELETE') {
        return next();
    }
    // Check for valid JSON or merge-patch+json
    if (!req.is('application/json') && !req.is('application/merge-patch+json')) {
        return res.status(415).json({
            error: 'Unsupported Media Type',
            message: 'Content-Type must be application/json or application/merge-patch+json'
        });
    }
    next();
};

// Middleware
app.use(bodyParser.json({
    verify: (req, res, buf) => {
        try {
            JSON.parse(buf);
        } catch (e) {
            res.status(400).json({
                error: 'Invalid JSON',
                message: 'Request body contains invalid JSON'
            });
        }
    }
}));
app.use(validateRequest);

// API version
app.use((req, res, next) => {
    res.setHeader('API-Version', '1.0.0');
    next();
});

// POST: Create Data
app.post('/data', authenticateToken, async (req, res, next) => {
    try {
        // Type validation
        const typeErrors = validateTypes(req.body);
        if (typeErrors.length > 0) {
            return res.status(400).json({
                error: 'Type Validation Failed',
                details: typeErrors
            });
        }

        // Schema validation
        const validate = ajv.compile(schema);
        if (!validate(req.body)) {
            return res.status(400).json({
                error: 'Schema Validation Failed',
                details: validate.errors.map(error => ({
                    path: error.instancePath || '/',
                    message: error.message,
                    keyword: error.keyword,
                    params: error.params
                }))
            });
        }

        const { objectId } = req.body;

        // Check for existing data
        const existing = await redisClient.get(objectId);
        if (existing) {
            return res.status(409).json({
                error: 'Conflict',
                message: `Data with objectId '${objectId}' already exists`
            });
        }

        // Store data with metadata
        const dataToStore = {
            ...req.body,
            _metadata: {
                createdBy: req.user.sub || req.user.email,
                createdAt: new Date().toISOString(),
                version: 1
            }
        };

        await redisClient.set(objectId, JSON.stringify(dataToStore));

        // Generate ETag for the resource
        const etag = crypto.createHash('md5').update(JSON.stringify(dataToStore)).digest('hex');

        res.setHeader('ETag', etag);
        res.status(201).json(dataToStore);
    } catch (error) {
        next(error);
    }
});

// GET: Retrieve Data with specific user
app.get('/data/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const data = await redisClient.get(id);
        
        if (!data) {
            return res.status(404).json({
                error: 'Not Found',
                message: `No data found for id '${id}'`
            });
        }

        const parsedData = JSON.parse(data);
        const etag = crypto.createHash('md5').update(data).digest('hex');

        res.setHeader('ETag', etag);
        
        // Conditional GET - If-None-Match
        if (req.headers['if-none-match'] === etag) {
            return res.status(304).end();
        }

        // Conditional GET - If-Modified-Since
        if (req.headers['if-modified-since']) {
            const ifModifiedSince = new Date(req.headers['if-modified-since']);
            const lastModified = new Date(parsedData._metadata?.createdAt || parsedData._metadata?.updatedAt);
            
            if (lastModified <= ifModifiedSince) {
                return res.status(304).end();
            }
        }

        res.status(200).json(parsedData);
    } catch (error) {
        next(error);
    }
});

// GET: Retrieve all data
app.get('/data', authenticateToken, async (req, res, next) => {
    try {
        const keys = await redisClient.keys('*'); // Get all keys in Redis
        if (keys.length === 0) {
            return res.status(404).json({
                error: 'Not Found',
                message: 'No data found'
            });
        }

        const dataPromises = keys.map(async (key) => {
            const data = await redisClient.get(key);
            try {
                return JSON.parse(data); // Try parsing as JSON
            } catch (e) {
                return { error: 'Invalid JSON', message: `Data for key '${key}' is not valid JSON` };
            }
        });

        const allData = await Promise.all(dataPromises);

        res.status(200).json(allData);
    } catch (error) {
        next(error);
    }
});





// PATCH: Partial Update/Merge Data
app.patch('/data/:id', authenticateToken, async (req, res, next) => {
    try {
        if (!req.body || Object.keys(req.body).length === 0) {
            return res.status(400).json({ error: 'Bad Request', message: 'No JSON body received' });
        }

        const { id } = req.params;
        console.log(`PATCH /data/${id} called with body:`, req.body);
 
        const existingData = await redisClient.get(id);
        if (!existingData) {
            return res.status(404).json({
                error: 'Not Found',
                message: `No data found for id '${id}'`
            });
        }
 
        const parsedExisting = JSON.parse(existingData);
        console.log(`Existing data for id ${id}:`, parsedExisting);
 
        const currentEtag = crypto.createHash('md5').update(existingData).digest('hex');
 
        if (req.headers['if-match'] && req.headers['if-match'] !== currentEtag) {
            return res.status(412).json({
                error: 'Precondition Failed',
                message: 'Resource has been modified since last retrieval'
            });
        }
 
        // Overwrite fields with new values
        const updatedData = { 
            ...parsedExisting, 
            ...req.body, 
            _metadata: {
                ...parsedExisting._metadata,
                updatedBy: req.user.sub || req.user.email,
                updatedAt: new Date().toISOString(),
                version: (parsedExisting._metadata?.version || 0) + 1
            }
        };
 
        console.log('Updated data before saving:', updatedData);
 
        // Save to Redis
        const redisSetResult = await redisClient.set(id, JSON.stringify(updatedData));
        console.log('Redis set result:', redisSetResult); // Should log 'OK'
 
        // Verify data persistence
        const verifySave = await redisClient.get(id);
        console.log('Data in Redis after save:', JSON.parse(verifySave));
 
        // Generate new ETag
        const newEtag = crypto.createHash('md5').update(JSON.stringify(updatedData)).digest('hex');
 
        res.setHeader('ETag', newEtag);
        res.status(200).json(updatedData);
    } catch (error) {
        console.error('Error in PATCH:', error);
        next(error);
    }
});


function isObject(item) {
    return (item && typeof item === 'object' && !Array.isArray(item));
}


// DELETE: Remove Data
app.delete('/data/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        // Get existing data for ETag check
        const existingData = await redisClient.get(id);
        
        if (!existingData) {
            return res.status(404).json({
                error: 'Not Found',
                message: `No data found for id '${id}'`
            });
        }
        
        // Compute current ETag
        const currentEtag = crypto.createHash('md5').update(existingData).digest('hex');
        
        // Conditional delete - If-Match
        if (req.headers['if-match'] && req.headers['if-match'] !== currentEtag) {
            return res.status(412).json({
                error: 'Precondition Failed',
                message: 'Resource has been modified since last retrieval'
            });
        }
        
        // Delete the resource
        const result = await redisClient.del(id);
        
        res.status(200).json({
            message: 'Data deleted successfully',
            objectId: id
        });
    } catch (error) {
        next(error);
    }
});

// Error handling middleware should be last
app.use(errorHandler);

// Start Server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});