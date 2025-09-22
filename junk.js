const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken'); // Will use for your custom JWTs
const admin = require('firebase-admin'); // Firebase Admin SDK


const app = express();
const port = process.env.PORT || 3000

app.use(cors());
app.use(express.json());



//username: LifeStream
//password: UG4QVZYXDNdbAdzr

// --- IMPORTANT: Configure CORS for your frontend URL ---
// Make sure to replace 'http://localhost:5173' with your actual frontend domain in production
const corsOptions = {
    origin: ['http://localhost:5173', 'https://your-frontend-domain.com'], // Add your frontend domain here
    credentials: true, // Allow cookies to be sent (if you use HttpOnly cookies for refresh tokens)
    optionsSuccessStatus: 200 // Some legacy browsers (IE11, various SmartTVs) choke on 204
};

// --- Firebase Admin SDK Initialization ---
// IMPORTANT: Replace './path/to/your/serviceAccountKey.json' with the actual path
// This file should NOT be committed to your public Git repository!
const serviceAccount = require('./serviceAccountKey.json'); // Adjust path as needed

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});
// --- End Firebase Admin SDK Initialization ---




//// Connection URI
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@mdbcluster01.xglsjy7.mongodb.net/?retryWrites=true&w=majority&appName=MDBCluster01`;


// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// --- Middleware to Verify Firebase ID Token ---
const verifyFirebaseToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send({ message: 'Unauthorized: No token provided' });
    }

    const idToken = authHeader.split(' ')[1];

    console.log('Verifying Firebase ID token:', idToken);

    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        req.firebaseUser = decodedToken; // Attach decoded Firebase user info to request (uid, email, etc.)
        next();
    } catch (error) {
        console.error('Error verifying Firebase ID token:', error.message);
        if (error.code === 'auth/id-token-expired') {
            return res.status(401).send({ message: 'Unauthorized: Token expired. Please re-authenticate.' });
        }
        return res.status(403).send({ message: 'Forbidden: Invalid token' });
    }
};
// --- End Firebase Token Verification Middleware ---

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();

        // Create a collection for bookingss and hotels
        // const hotelCollection = client.db("StayDwell").collection("Hotels");
        // const bookingCollection = client.db("StayDwell").collection("Bookings");
        const userCollection = client.db("LifeStream").collection("Users");

        // --- Custom JWT Generation Endpoint ---
        // This endpoint receives the Firebase ID token and issues your custom JWT.
        app.post('/jwt', verifyFirebaseToken, async (req, res) => {
            // If we reach here, req.firebaseUser is already populated by verifyFirebaseToken middleware.
            const firebaseUid = req.firebaseUser.uid;
            const firebaseEmail = req.firebaseUser.email; // Or other info from decoded token

            // Optional: You might want to store/find user details in your own MongoDB here
            // let userInDb = await userCollection.findOne({ firebaseUid: firebaseUid });
            // if (!userInDb) {
            //     userInDb = await userCollection.insertOne({ firebaseUid: firebaseUid, email: firebaseEmail, createdAt: new Date() });
            // }

            // Create your custom payload based on your application's needs
            const customPayload = {
                uid: firebaseUid,
                email: firebaseEmail,
                // You can add roles or other app-specific claims here
                // role: userInDb.role || 'user'
            };

            // Sign your custom JWT
            const customAccessToken = jwt.sign(customPayload, process.env.JWT_ACCESS_SECRET, { expiresIn: '1h' }); // Short-lived access token

            // Optional: Generate and set a HttpOnly refresh token (for long sessions)
            // if you need refresh tokens, uncomment cookie-parser above and implement refresh logic
            // const refreshToken = jwt.sign({ uid: firebaseUid }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
            // res.cookie('refreshToken', refreshToken, {
            //     httpOnly: true,
            //     secure: process.env.NODE_ENV === 'production', // Use secure in production (HTTPS)
            //     sameSite: 'strict', // Adjust based on your frontend/backend domain relationship
            //     maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
            // });

            res.send({ success: true, token: customAccessToken });
        });



        // app.get('/tophotels', async (req, res) => {
        //     try {
        //         const result = await hotelCollection.find() // Start with an empty query to find all
        //             .sort({ total_ratings: -1 }) // Sort by 'likes' field in descending order (most liked first)
        //             .limit(6)           // Limit the results to 6 documents
        //             .toArray();         // Convert the cursor to an array

        //         res.send(result);
        //     } catch (error) {
        //         console.error("Error fetching most liked public tips:", error);
        //         res.status(500).send({ message: "Failed to fetch tips", error: error.message });
        //     }
        // });

        // app.get('/browserooms', async (req, res) => {
        //     try {
        //         const result = await hotelCollection.find()
        //             .sort({ likes: -1 }) // Sort by 'likes' field in descending order (most liked first)
        //             .toArray();         // Convert the cursor to an array

        //         res.send(result);
        //     } catch (error) {
        //         console.error("Error fetching most liked public tips:", error);
        //         res.status(500).send({ message: "Failed to fetch tips", error: error.message });
        //     }
        // });



        //Get a single hotel by ID

        app.get('/user/:id', async (req, res) => {
            try {
                const userId = req.params.id; // Get the Hotel ID directly as a string

                // Query by the string hotel_id directly. Now changed to use ObjectId for MongoDB compatibility.
                const query = { uid: userId }; // Query by string userId

                // const query = { _id: new ObjectId(userId) };

                const result = await userCollection.findOne(query); // Use findOne as we expect a single document
                // If the hotel is not found, result will be null
                if (result) {
                    res.send(result);
                } else {
                    res.status(404).send({ message: "User not found" });
                }
            } catch (error) {
                console.error("Error fetching user data:", error);
                res.status(500).send({ message: "Failed to fetch user data", error: error.message });
            }
        });

        // app.get('/bookings/:id', async (req, res) => {
        //     try {
        //         const hotelId = req.params.id; // Get the Hotel ID directly as a string

        //         // Query by the string hotel_id directly. Now changed to use ObjectId for MongoDB compatibility.
        //         // const query = { hotel_id: hotelId };

        //         const query = { _id: new ObjectId(hotelId) }; // Query by string hotelId

        //         const result = await hotelCollection.findOne(query); // Use findOne as we expect a single document
        //         // If the hotel is not found, result will be null
        //         if (result) {
        //             res.send(result);
        //         } else {
        //             res.status(404).send({ message: "Hotel not found" });
        //         }
        //     } catch (error) {
        //         console.error("Error fetching hotel data:", error);
        //         res.status(500).send({ message: "Failed to fetch hotel data", error: error.message });
        //     }
        // });

        //Get bookings by a user using firebase user ID
        // app.get('/mybookings/:id', async (req, res) => {
        //     try {
        //         const userId = req.params.id; // Get the user ID directly as a string
        //         const query = { userId: userId }; // Query by string userId
        //         console.log("Fetching bookings for user ID:", userId);

        //         const result = await bookingCollection.find(query).toArray(); // Filter by a specific user ID"
        //         res.send(result);
        //     } catch (error) {
        //         console.error("Error fetching my tips:", error);
        //         res.status(500).send({ message: "Failed to fetch tips", error: error.message });
        //     }
        // });






        // app.get('/allbookings', async (req, res) => {
        //     try {
        //         const result = await bookingCollection.find() // Start with an empty query to find all
        //             .toArray();         // Convert the cursor to an array

        //         res.send(result);
        //     } catch (error) {
        //         console.error("Error fetching most liked public tips:", error);
        //         res.status(500).send({ message: "Failed to fetch tips", error: error.message });
        //     }
        // });

        app.get('/allusers', async (req, res) => {
            try {
                const result = await userCollection.find() // Start with an empty query to find all
                    .toArray();         // Convert the cursor to an array

                res.send(result);
            } catch (error) {
                console.error("Error fetching most liked public tips:", error);
                res.status(500).send({ message: "Failed to fetch tips", error: error.message });
            }
        });



        // app.post('/bookings', async (req, res) => {
        //     const newBooking = req.body;
        //     console.log(newBooking);
        //     const result = await bookingCollection.insertOne(newBooking);
        //     res.send(result);

        // });

        // app.post('/Users', async (req, res) => {
        //     const newUser = req.body;
        //     console.log(newUser);
        //     const result = await bookingCollection.insertOne(newUser);
        //     res.send(result);

        // });

        app.post('/Users', async (req, res) => {
            try {
                const userData = req.body;
                // Save userData to your database here
                console.log('Received user data:', userData);
                const result = await userCollection.insertOne(userData);
                res.status(201).json({ message: 'User data saved successfully', data: userData });
            } catch (error) {
                console.error('Error saving user data to DB:', error);
                res.status(500).json({ message: 'Failed to save user data', error: error.message });
            }
        });

        // app.put('/updateuser/:id', async (req, res) => {
        //     const id = req.params.id;
        //     const filter = { uid: id }; // Query by string userId
        //     //const filter = { _id: new ObjectId(id) };
        //     const updatedBooking = req.body;
        //     delete updatedBooking._id
        //     const options = { upsert: true };
        //     const updateDoc = {
        //         $set: { ...updatedBooking },
        //     };
        //     const result = await bookingCollection.updateOne(filter, updateDoc, options);
        //     res.send(result);
        // }
        // );

        // Update existing user data (from frontend UserProfile page)
        // IMPORTANT: Added verifyFirebaseToken middleware for security
        app.put('/updateuser/:id', verifyFirebaseToken, async (req, res) => {
            const userIdFromParams = req.params.id;
            const userIdFromToken = req.firebaseUser.uid; // Get UID from verified token

            // Security check: Ensure the user trying to update is the owner of the profile
            if (userIdFromParams !== userIdFromToken) {
                return res.status(403).send({ message: 'Forbidden: You can only update your own profile.' });
            }

            try {
                const updatedData = req.body;
                // Remove _id if present to prevent MongoDB errors on update
                delete updatedData._id;

                console.log(`Received update request for user ${userIdFromParams}:`, updatedData);

                const filter = { uid: userIdFromParams }; // Filter by UID
                const options = { upsert: false }; // Do not create if not exists, just update
                const updateDoc = {
                    $set: {
                        ...updatedData,
                        updatedAt: new Date().toISOString() // Add an update timestamp
                    },
                };

                // FIX: Use userCollection instead of bookingCollection
                const result = await userCollection.updateOne(filter, updateDoc, options);

                if (result.matchedCount === 0) {
                    return res.status(404).send({ message: "User not found for update." });
                }

                res.send({ message: 'User profile updated successfully', result });
            } catch (error) {
                console.error("Error updating user profile in DB:", error);
                res.status(500).send({ message: "Failed to update user profile", error: error.message });
            }
        });

        app.get("/get-user-role", verifyFirebaseToken, async (req, res) => {
            const user = await userCollection.findOne({
                email: req.firebaseUser.email,
            });
            res.send({ msg: "ok", role: user.role, status: "active" });
        });


        //delete a booing

        // app.delete('/allbookings/:id', async (req, res) => {
        //     const id = req.params.id;
        //     console.log("Deleting booking with ID:", id);

        //     const query = { _id: new ObjectId(id) };
        //     const result = await bookingCollection.deleteOne(query);
        //     res.send(result);
        // });

        // Send a ping to confirm a successful connection

        // await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);


app.get('/', (req, res) => {
    res.send('Save Lives...Donate Blood...Save Lives!');
})

app.listen(port, () => {

    console.log(`LifeStream server is running on port ${port}`)
})


const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin'); // Firebase Admin SDK
const Stripe = require('stripe');
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

const app = express();
const port = process.env.PORT || 3000;

// --- IMPORTANT: Configure CORS for your frontend URL ---
const corsOptions = {
    origin: ['http://localhost:5173', 'https://your-frontend-domain.com'], // Add your frontend domain here
    credentials: true,
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions)); // Apply CORS middleware
app.use(express.json()); // To parse JSON request bodies
app.use(cookieParser()); // If you plan to use HttpOnly cookies for refresh tokens

// --- Firebase Admin SDK Initialization ---
const serviceAccount = require('./serviceAccountKey.json'); // Adjust path as needed
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});
// --- End Firebase Admin SDK Initialization ---

//// Connection URI
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@mdbcluster01.xglsjy7.mongodb.net/?retryWrites=true&w=majority&appName=MDBCluster01`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// --- Middleware to Verify Firebase ID Token ---
const verifyFirebaseToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send({ message: 'Unauthorized: No token provided' });
    }

    const idToken = authHeader.split(' ')[1];

    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        req.firebaseUser = decodedToken; // Attach decoded Firebase user info to request (uid, email, etc.)
        next();
    } catch (error) {
        console.error('Error verifying Firebase ID token:', error.message);
        if (error.code === 'auth/id-token-expired') {
            return res.status(401).send({ message: 'Unauthorized: Token expired. Please re-authenticate.' });
        }
        return res.status(403).send({ message: 'Forbidden: Invalid token' });
    }
};
// --- End Firebase Token Verification Middleware ---

async function run() {
    try {
        await client.connect();

        const userCollection = client.db("LifeStream").collection("Users"); // Correct collection reference
        const requestCollection = client.db("LifeStream").collection("Requests"); // Correct collection reference
        const blogCollection = client.db("LifeStream").collection("Blog"); // Correct collection reference
        const donationCollection = client.db("LifeStream").collection("Donations"); // Correct collection reference


        // --- Custom JWT Generation Endpoint ---
        app.post('/jwt', verifyFirebaseToken, async (req, res) => {
            const firebaseUid = req.firebaseUser.uid;
            const firebaseEmail = req.firebaseUser.email;

            const customPayload = {
                uid: firebaseUid,
                email: firebaseEmail,
                // Add roles or other app-specific claims from your DB if available
            };

            const customAccessToken = jwt.sign(customPayload, process.env.JWT_ACCESS_SECRET, { expiresIn: '1h' });

            res.send({ success: true, token: customAccessToken });
        });

        // Get a single user by UID
        app.get('/user/:id', async (req, res) => {
            try {
                const userId = req.params.id;
                const query = { uid: userId }; // Query by string uid
                const result = await userCollection.findOne(query); // Use userCollection
                if (result) {
                    res.send(result);
                } else {
                    res.status(404).send({ message: "User not found in database" });
                }
            } catch (error) {
                console.error("Error fetching user data:", error);
                res.status(500).send({ message: "Failed to fetch user data", error: error.message });
            }
        });



        // Get all users (for admin purposes, protected)
        app.get('/allusers', verifyFirebaseToken, async (req, res) => { // Added verifyFirebaseToken middleware
            try {
                const userFromToken = req.firebaseUser; // User data from the verified Firebase token
                const dbUser = await userCollection.findOne({ uid: userFromToken.uid });

                // if (!dbUser || dbUser.role !== 'admin') {
                if (!dbUser) {
                    console.warn(`Unauthorized access attempt to /allusers by UID: ${userFromToken.uid || 'N/A'}`);
                    return res.status(403).send({ message: "Forbidden: You do not have admin access." });
                }

                const result = await userCollection.find().toArray();

                console.log(`Fetched ${result.length} users from the database):`, result);
                res.status(200).json(result); // Use .json() for sending JSON data
            } catch (error) {
                console.error("Error fetching all users:", error);
                res.status(500).send({ message: "Failed to fetch users", error: error.message });
            }
        });

        // Endpoint to get the total count of all users (for admin purposes, protected)
        app.get('/allusers-count', verifyFirebaseToken, async (req, res) => {
            try {
                const userFromToken = req.firebaseUser; // User data from the verified Firebase token
                const dbUser = await userCollection.findOne({ uid: userFromToken.uid });
                console.log(`User role from token: ${dbUser.role}`);

                if (!dbUser) {
                    console.warn(`Unauthorized access attempt to /admin/stats/users by UID: ${userFromToken.uid || 'N/A'}`);
                    return res.status(403).send({ message: "Admin/Volunteer User not logged in." });
                }

                const count = await userCollection.countDocuments({});
                res.status(200).json({ count });
            } catch (error) {
                console.error("Error fetching total users count for admin dashboard:", error);
                res.status(500).send({ message: "Failed to fetch total users count", error: error.message });
            }
        });

        // Register new user data (from frontend Register page)
        app.post('/Users', async (req, res) => {
            try {
                const userData = req.body;
                //console.log('Received new user data for registration:', userData);
                const existingUser = await userCollection.findOne({ uid: userData.uid });
                if (existingUser) {
                    console.warn(`User with UID ${userData.uid} already exists in DB. Not inserting again.`);
                    return res.status(200).json({ message: 'User data already exists', data: existingUser });
                }

                const result = await userCollection.insertOne(userData);
                res.status(201).json({ message: 'User data saved successfully', insertedId: result.insertedId, data: userData });
            } catch (error) {
                console.error('Error saving new user data to DB:', error);
                res.status(500).json({ message: 'Failed to save new user data', error: error.message });
            }
        });

        app.put('/updateuser/:uid', verifyFirebaseToken, async (req, res) => {
            const { uid } = req.params;
            const { name, photoURL, bloodGroup, district, upazila } = req.body;

            // Check if the UID from the token matches the UID in the URL
            if (req.firebaseUser.uid !== uid) { // Use req.firebaseUser
                return res.status(403).json({ message: 'Unauthorized. You can only update your own profile.' });
            }

            try {
                const filter = { uid: uid }; // Query filter
                const updateDoc = {
                    $set: { // Use the $set operator to update fields
                        name,
                        photoURL,
                        bloodGroup,
                        district,
                        upazila
                    }
                };
                const result = await userCollection.updateOne(filter, updateDoc); // Use userCollection

                if (result.matchedCount === 0) {
                    return res.status(404).json({ message: 'User not found.' });
                }

                res.status(200).json({ message: 'User profile updated successfully!' });
            } catch (error) {
                console.error('Error updating user profile:', error);
                res.status(500).json({ message: 'Internal Server Error' });
            }
        });

        app.post('/save-donation', async (req, res) => {
            try {
                const donationData = req.body;
                console.log('Received new donation data:', donationData);
                const result = await donationCollection.insertOne(donationData);
                res.status(201).json({ message: 'User data saved successfully', insertedId: result.insertedId, data: donationData });
            } catch (error) {
                console.error('Error saving ned Donation data to DB:', error);
                res.status(500).json({ message: 'Failed to save new Donation data', error: error.message });
            }
        });

        app.get('/total-donations', async (req, res) => {
            try {
                // Corrected: Use the already defined `donationCollection` variable
                const result = await donationCollection.aggregate([
                    {
                        $group: {
                            _id: null, // Group all documents together
                            totalAmount: { $sum: "$amount" } // Sum the 'amount' field
                        }
                    }
                ]).toArray();
                console.log('Total donations aggregation result:', result);

                // Check if there are any results
                if (result.length > 0) {
                    const totalAmount = result[0].totalAmount;
                    res.status(200).json({ totalAmount: totalAmount });
                } else {
                    // No donations found
                    res.status(200).json({ totalAmount: 0 });
                }
            } catch (error) {
                console.error('Error fetching total donations:', error);
                res.status(500).send('Failed to fetch total donation data.');
            }
        });
        app.get("/get-user-role", verifyFirebaseToken, async (req, res) => {
            try {
                const user = await userCollection.findOne({
                    email: req.firebaseUser.email,
                });

                let userRole = 'donor'; // Default role
                let userStatus = 'active'; // Default status

                if (user) {
                    userRole = user.role || 'donor'; // Fallback to 'donor' if role is missing in DB
                    userStatus = user.status || 'active'; // Fallback to 'active' if status is missing in DB
                } else {
                    console.warn(`User with email ${req.firebaseUser.email} not found in DB. Assigning default role 'donor' and status 'active'.`);
                }

                res.send({ msg: "ok", role: userRole, status: userStatus });
            } catch (error) {
                console.error("Error in /get-user-role:", error);
                res.status(500).send({ message: "Failed to fetch user role", error: error.message });
            }
        });

        // Endpoint to update a user's role and status (Admin only)
        app.put('/set-user-role/:uid', verifyFirebaseToken, async (req, res) => {
            try {
                const userToUpdateUid = req.params.uid;
                const { role, status } = req.body;

                console.log(`Received request to update user role for UID: ${userToUpdateUid} with role: ${role} and status: ${status}`);

                const userFromToken = req.firebaseUser;
                const dbUser = await userCollection.findOne({ uid: userFromToken.uid });

                if (dbUser?.role !== 'admin') {
                    console.warn(`Unauthorized role update attempt by UID: ${userFromToken.uid} with role: ${dbUser?.role}`);
                    return res.status(403).send({ message: "Forbidden: Only admins can change user roles." });
                }

                if (!userToUpdateUid || !role || !status) {
                    return res.status(400).send({ message: "Bad Request: Missing UID, role, or status in the request." });
                }

                if (userToUpdateUid === userFromToken.uid) {
                    return res.status(403).send({ message: "Forbidden: Admins cannot change their own role or status." });
                }

                const filter = { _id: new ObjectId(userToUpdateUid) };
                const updateDoc = {
                    $set: {
                        role: role,
                        status: status,
                        updatedAt: new Date().toISOString()
                    },
                };

                const result = await userCollection.updateOne(filter, updateDoc);
                console.log(`Update result for UID ${userToUpdateUid}:`, result);

                if (result.matchedCount === 0) {
                    return res.status(404).send({ message: "User not found for update." });
                }

                res.status(200).send({ message: `Successfully updated role for user ${userToUpdateUid} to ${role} and status to ${status}.` });

            } catch (error) {
                console.error("Error updating user role:", error);
                res.status(500).send({ message: "Failed to update user role", error: error.message });
            }
        });

        // This API endpoint searches for donors based on blood group, district, and upazila.
        // It uses a GET request with query parameters.
        app.get('/search-donors', async (req, res) => {
            try {
                // Extract query parameters from the request URL
                const { bloodGroup, district, upazila } = req.query;

                // Start with an empty filter object for the MongoDB query
                const filter = {};

                // Build the filter dynamically based on the provided query parameters
                if (bloodGroup) {
                    filter.bloodGroup = bloodGroup;
                }

                if (district) {
                    filter.district = district;
                }

                if (upazila) {
                    filter.upazila = upazila;
                }

                // Match the donor based on their role, as found in your user data schema.
                // The role field must be exactly "donor".
                filter.role = "donor";

                // We will not add a filter for "availabilityStatus" as it is not present in your provided schema.
                // The query will still work with the "status: active" field if you need it.
                if (req.query.status) {
                    filter.status = req.query.status;
                } else {
                    // Default to 'active' status if no status is provided in the query
                    filter.status = "active";
                }

                // Query the 'userCollection' with the constructed filter
                // We use .find() to get all matching documents and .toArray() to convert the cursor to an array.
                const donors = await userCollection.find(filter).toArray();

                // Check if any donors were found
                if (donors.length === 0) {
                    return res.status(404).json({ message: "No donors found matching the criteria." });
                }

                // Return the found donors as a JSON response
                res.status(200).json(donors);

            } catch (error) {
                // Log the full error to the console for debugging purposes
                console.error('Backend: Error searching for donors:', error);

                // Send a 500 status code with a user-friendly error message
                res.status(500).json({ message: 'Failed to search for donors', error: error.message });
            }
        });


        // Endpoint to toggle a user's status (block/unblock)
        app.put('/toggle-user-status/:id', verifyFirebaseToken, async (req, res) => {
            try {
                const userToUpdateId = req.params.id; // This is the user's MongoDB _id
                const { newStatus } = req.body;

                const userFromToken = req.firebaseUser;
                const dbUser = await userCollection.findOne({ uid: userFromToken.uid });

                if (dbUser?.role !== 'admin') {
                    console.warn(`Unauthorized status update attempt by UID: ${userFromToken.uid} with role: ${dbUser?.role}`);
                    return res.status(403).send({ message: "Forbidden: Only admins can change user status." });
                }

                if (!userToUpdateId || !newStatus) {
                    return res.status(400).send({ message: "Bad Request: Missing user ID or new status." });
                }

                if (newStatus !== 'active' && newStatus !== 'blocked') {
                    return res.status(400).send({ message: "Bad Request: Status must be either 'active' or 'blocked'." });
                }

                if (userToUpdateId === dbUser._id.toString()) {
                    return res.status(403).send({ message: "Forbidden: Admins cannot change their own status." });
                }

                const filter = { _id: new ObjectId(userToUpdateId) };
                const updateDoc = {
                    $set: {
                        status: newStatus,
                        updatedAt: new Date().toISOString()
                    },
                };

                const result = await userCollection.updateOne(filter, updateDoc);
                console.log(`Status update result for ID ${userToUpdateId}:`, result);

                if (result.matchedCount === 0) {
                    return res.status(404).send({ message: "User not found for update." });
                }

                res.status(200).send({ message: `Successfully updated status for user ${userToUpdateId} to ${newStatus}.` });

            } catch (error) {
                console.error("Error updating user status:", error);
                res.status(500).send({ message: "Failed to update user status", error: error.message });
            }
        });

        // Register new user blood donation request (from frontend DonationRequest page)
        app.post('/create-donation-request', async (req, res) => {
            try {
                const requestData = req.body;
                console.log('Received new donation request:', requestData);
                const result = await requestCollection.insertOne(requestData);
                res.status(201).json({ message: 'User data saved successfully', insertedId: result.insertedId, data: requestData });
            } catch (error) {
                console.error('Error saving new user data to DB:', error);
                res.status(500).json({ message: 'Failed to save new user data', error: error.message });
            }
        });

        // Post new Blog data (from frontend Blog page)
        app.post('/post-blog', verifyFirebaseToken, async (req, res) => {
            try {
                const userFromToken = req.firebaseUser;
                const blogData = req.body;

                console.log(`Received new blog data from UID: ${userFromToken.uid}`);

                const dbUser = await userCollection.findOne({ uid: userFromToken.uid });

                if (dbUser?.role !== 'admin' && dbUser?.role !== 'volunteer') {
                    console.warn(`Unauthorized blog post attempt by UID: ${userFromToken.uid} with role: ${dbUser?.role}`);
                    return res.status(403).send({ message: "Forbidden: Only admins and volunteers can create blog posts." });
                }

                blogData.authorUid = userFromToken.uid;
                blogData.authorEmail = userFromToken.email;
                blogData.createdAt = new Date().toISOString();

                const result = await blogCollection.insertOne(blogData);

                res.status(201).json({ message: 'Blog post created successfully', insertedId: result.insertedId });
            } catch (error) {
                console.error('Error saving new blog data to DB:', error);
                res.status(500).json({ message: 'Failed to save new blog post', error: error.message });
            }
        });

        // Fetch all blog posts
        app.get('/blogs', verifyFirebaseToken, async (req, res) => {
            try {
                const allBlogs = await blogCollection.find({})
                    .sort({ createdAt: -1 })
                    .toArray();

                res.status(200).json(allBlogs);
                console.log(`Fetched ${allBlogs.length} blog posts from the database.`);
            } catch (error) {
                console.error('Error fetching blog posts:', error);
                res.status(500).json({ message: 'Failed to fetch blog posts', error: error.message });
            }
        });

        app.put('/toggle-blog-status/:id', verifyFirebaseToken, async (req, res) => {
            try {
                const blogId = req.params.id;
                const userFromToken = req.firebaseUser;

                // 1. Get the user's role from the database to check for admin/volunteer status
                const dbUser = await userCollection.findOne({ uid: userFromToken.uid });

                if (!dbUser || (dbUser.role !== 'admin' && dbUser.role !== 'volunteer')) {
                    console.warn(`Unauthorized status toggle attempt by UID: ${userFromToken.uid}`);
                    return res.status(403).send({ message: "Forbidden: You do not have permission to perform this action." });
                }

                // 2. Find the blog post by its ID
                const filter = { _id: new ObjectId(blogId) };
                const blogPost = await blogCollection.findOne(filter);

                if (!blogPost) {
                    return res.status(404).send({ message: "Blog post not found." });
                }

                // 3. Determine the new status
                const newStatus = blogPost.status === 'published' ? 'draft' : 'published';

                // 4. Update the document with the new status
                const updateDoc = {
                    $set: {
                        status: newStatus,
                        updatedAt: new Date().toISOString()
                    },
                };

                const result = await blogCollection.updateOne(filter, updateDoc);

                if (result.matchedCount === 0) {
                    return res.status(404).send({ message: "Blog post not found or no changes were made." });
                }

                res.status(200).send({
                    message: `Blog status successfully changed to "${newStatus}".`,
                    newStatus: newStatus
                });

            } catch (error) {
                console.error('Error toggling blog status:', error);
                res.status(500).send({ message: "Failed to toggle blog status.", error: error.message });
            }
        });

        //Delete a blog post
        app.delete('/delete-blog/:id', verifyFirebaseToken, async (req, res) => {
            try {
                const blogId = req.params.id;
                const userFromToken = req.firebaseUser;
                const dbUser = await userCollection.findOne({ uid: userFromToken.uid });
                if (!dbUser || (dbUser.role !== 'admin' && dbUser.role !== 'volunteer')) {
                    console.warn(`Unauthorized blog delete attempt by UID: ${userFromToken.uid}`);
                    return res.status(403).send({ message: "Forbidden: You do not have permission to perform this action." });
                }
                const filter = { _id: new ObjectId(blogId) };
                const result = await blogCollection.deleteOne(filter);
                if (result.deletedCount === 0) {
                    return res.status(404).send({ message: "Blog post not found or already deleted." });
                }
                res.status(200).send({ message: "Blog post successfully deleted." });
            } catch (error) {
                console.error('Error deleting blog post:', error);
                res.status(500).send({ message: "Failed to delete blog post.", error: error.message });
            }
        });

        app.get('/donationRequests/recent/:uid', verifyFirebaseToken, async (req, res) => {
            const userIdFromParams = req.params.uid;
            const userIdFromToken = req.firebaseUser.uid;

            if (userIdFromParams !== userIdFromToken) {
                return res.status(403).send({ message: 'Forbidden: You can only view your own requests.' });
            }

            try {
                const recentRequests = await requestCollection.find({ uid: userIdFromParams })
                    .sort({ createdAt: -1 })
                    .limit(3)
                    .toArray();

                res.status(200).json(recentRequests);
            } catch (error) {
                console.error('Backend: Error fetching recent donation requests:', error);
                res.status(500).json({ message: 'Failed to fetch recent donation requests', error: error.message });
            }
        });


        app.get(`/donationRequests/:id`, verifyFirebaseToken, async (req, res) => {
            const requestId = req.params.id;
            const userIdFromToken = req.firebaseUser.uid;
            try {
                const query = { _id: new ObjectId(requestId) };
                const request = await requestCollection.findOne(query);
                if (!request) {
                    return res.status(404).json({ message: "Donation request not found." });
                }

                res.status(200).json(request);
            } catch (error) {
                console.error('Backend: Error fetching single donation request:', error);
                res.status(500).json({ message: 'Failed to fetch donation request', error: error.message });
            }
        });

        app.get('/my-donation-requests/:id', verifyFirebaseToken, async (req, res) => {
            const userIdFromParams = req.params.id;
            const userIdFromToken = req.firebaseUser.uid;

            if (userIdFromParams !== userIdFromToken) {
                return res.status(403).send({ message: 'Forbidden: You can only view your own donation history.' });
            }

            try {

                const myDonations = await requestCollection.find(userIdFromParams ? { uid: userIdFromParams } : {})
                    .sort({ donationDate: -1, donationTime: -1 })
                    .toArray();

                res.status(200).json(myDonations);
            } catch (error) {
                console.error("Backend: Error fetching my donations:", error);
                res.status(500).send({ message: "Failed to fetch your donation history", error: error.message });
            }
        });

        app.get('/all-donation-requests', verifyFirebaseToken, async (req, res) => {

            try {
                const allDonationRequests = await requestCollection.find({})
                    .sort({ createdAt: -1 })
                    .toArray();

                res.status(200).json(allDonationRequests);
            } catch (error) {
                console.error("Backend: Error fetching all donation requests:", error);
                res.status(500).send({ message: "Failed to fetch all donation requests", error: error.message });
            }
        });

        app.get('/pendingRequests', async (req, res) => {

            try {
                const recentRequests = await requestCollection.find({ donationStatus: 'pending' })
                    .sort({ createdAt: -1 })
                    .limit(10)
                    .toArray();

                res.status(200).json(recentRequests);
                console.log(`Fetched ${recentRequests.length} pending requests from the database.`);
            } catch (error) {
                console.error('Backend: Error fetching recent donation requests:', error);
                res.status(500).json({ message: 'Failed to fetch recent donation requests', error: error.message });
            }
        });

        app.get('/all-donation-requests-count', verifyFirebaseToken, async (req, res) => {

            try {
                const userFromToken = req.firebaseUser;
                const dbUser = await userCollection.findOne({ uid: userFromToken.uid });

                if (!dbUser) {
                    console.warn(`Unauthorized access attempt to /admin/stats/users by UID: ${userFromToken.uid || 'N/A'}`);
                    return res.status(403).send({ message: "Admin/Volunteer User not logged in." });
                }

                const count = await requestCollection.countDocuments({});
                res.status(200).json({ count });
            } catch (error) {
                console.error("Error fetching total requests count for admin dashboard:", error);
                res.status(500).send({ message: "Failed to fetch total requests count", error: error.message });
            }
        });

        // app.get('/editDonationRequest/:id', verifyFirebaseToken, async (req, res) => {
        //     const requestId = req.params.id;
        //     const userIdFromToken = req.firebaseUser.uid;

        //     try {
        //         const query = { _id: new ObjectId(requestId) };
        //         const request = await requestCollection.findOne(query);

        //         if (!request) {
        //             return res.status(404).json({ message: "Donation request not found." });
        //         }

        //         if (request.uid !== userIdFromToken) {
        //             return res.status(403).json({ message: "Forbidden: You do not have permission to view this request." });
        //         }

        //         res.status(200).json(request);
        //     } catch (error) {
        //         console.error('Backend: Error fetching single donation request:', error);
        //         res.status(500).json({ message: 'Failed to fetch donation request', error: error.message });
        //     }
        // });

        app.put('/editDonationRequest/:id', verifyFirebaseToken, async (req, res) => {
            const requestId = req.params.id;
            const userIdFromToken = req.firebaseUser.uid;
            const updatedData = req.body; // The updated data sent from the frontend

            try {
                const query = { _id: new ObjectId(requestId) };
                const request = await requestCollection.findOne(query);

                if (!request) {
                    return res.status(404).json({ message: "Donation request not found." });
                }

                // Fetch the user's role from the database
                const dbUser = await userCollection.findOne({ uid: userIdFromToken });

                // Check if the user is the original creator or an admin/volunteer
                if (request.uid !== userIdFromToken && dbUser?.role !== 'admin' && dbUser?.role !== 'volunteer') {
                    return res.status(403).json({ message: "Forbidden: You do not have permission to edit this request." });
                }

                // Prepare the update document
                const updateDoc = {
                    $set: {
                        ...updatedData, // Use the data sent from the frontend
                        updatedAt: new Date().toISOString()
                    }
                };

                const result = await requestCollection.updateOne(query, updateDoc);

                if (result.matchedCount === 0) {
                    return res.status(404).json({ message: "Donation request not found or no changes were made." });
                }

                res.status(200).json({ message: "Donation request updated successfully." });
            } catch (error) {
                console.error('Backend: Error updating donation request:', error);
                res.status(500).json({ message: "Failed to update donation request", error: error.message });
            }
        });


        // --- Final connection confirmation and server start ---
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close(); // Keep the client open for continuous requests
    }
}
run().catch(console.dir);

// Start the Express server
app.get('/', (req, res) => {
    res.send('LifeStream server is running!');
});

app.listen(port, () => {
    console.log(`LifeStream server listening on port ${port}`);
});

