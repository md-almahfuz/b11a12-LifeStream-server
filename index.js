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
    origin: ['http://localhost:5173', 'https://aesthetic-tartufo-1f95c1.netlify.app'], // Add your frontend domain here
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
// const verifyFirebaseToken = async (req, res, next) => {
//     const authHeader = req.headers.authorization;
// edToken; // Attach decoded Firebase user info to request (uid, email, etc.)
//         next();
//     } catch (error) {
//         console.error('Error verifying Firebase ID token:', error.message);
//         if (error.code === 'auth/id-token-expired') {
//             return res.status(401).send({ message: 'Unauthorized: Token expired. Please re-authenticate.' });
//         }
//         return res.status(403).send({ message: 'Forbidden: Invalid token' });
//     }
// };

// NOTE: This file assumes you have initialized the Firebase Admin SDK
// and that the 'admin' object is available in this scope.

const verifyFirebaseToken = async (req, res, next) => {
    // 1. Check for the Authorization header
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        // Return 401 if the header is missing or not in the "Bearer <token>" format
        return res.status(401).send({ message: 'Unauthorized: No token provided or token format is invalid.' });
    }

    // 2. Extract the ID token (the part after "Bearer ")
    const idToken = authHeader.split('Bearer ')[1];

    // 3. Attempt to verify the token
    try {
        // The missing 'try' block starts here
        const decodedToken = await admin.auth().verifyIdToken(idToken);

        // Attach decoded Firebase user info to the request for downstream use
        req.user = decodedToken;

        // Continue to the next middleware or route handler
        next();
    } catch (error) {
        // The 'catch' block you had was missing its corresponding 'try'
        console.error('Error verifying Firebase ID token:', error.message);

        // Handle specific token expiry error
        if (error.code === 'auth/id-token-expired') {
            return res.status(401).send({ message: 'Unauthorized: Token expired. Please re-authenticate.' });
        }

        // Handle all other verification failures
        return res.status(403).send({ message: 'Forbidden: Invalid token' });
    }
};

// If this is in a separate file, make sure to export it
// module.exports = verifyFirebaseToken;

// --- End Firebase Token Verification Middleware ---

async function run() {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).send({ message: 'Unauthorized: No token provided' });
    }

    const idToken = authHeader.split(' ')[1];

    try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        req.firebaseUser = decod
        try {
            //await client.connect();

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

                    // console.log(`Fetched ${result.length} users from the database):`, result);
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
                    // console.log(`User role from token: ${dbUser.role}`);

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
                    //console.log('Received new donation data:', donationData);
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
                    // console.log('Total donations aggregation result:', result);

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

                    //  console.log(`Received request to update user role for UID: ${userToUpdateUid} with role: ${role} and status: ${status}`);

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
                    // console.log(`Update result for UID ${userToUpdateUid}:`, result);

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
                    //console.log(`Status update result for ID ${userToUpdateId}:`, result);

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
                    // console.log('Received new donation request:', requestData);
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

                    // console.log(`Received new blog data from UID: ${userFromToken.uid}`);

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
                    // console.log(`Fetched ${allBlogs.length} blog posts from the database.`);
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

            // Fetch recent donation requests for a specific user (limited to 3)
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

            // Fetch a single donation request by its ID
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

            // Fetch all donation requests made by a specific user
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

            // Fetch all donation requests (admin/volunteer only)
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

            // Fetch recent pending donation requests (limited to 10)
            app.get('/pendingRequests', async (req, res) => {

                try {
                    const recentRequests = await requestCollection.find({ donationStatus: 'pending' })
                        .sort({ createdAt: -1 })
                        .limit(10)
                        .toArray();

                    res.status(200).json(recentRequests);
                    //  console.log(`Fetched ${recentRequests.length} pending requests from the database.`);
                } catch (error) {
                    console.error('Backend: Error fetching recent donation requests:', error);
                    res.status(500).json({ message: 'Failed to fetch recent donation requests', error: error.message });
                }
            });

            // Endpoint to get the total count of all donation requests (for admin purposes, protected)
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

            // Endpoint to edit a donation request
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
                    const userRole = dbUser ? dbUser.role : 'donor';

                    const isOwner = request.uid === userIdFromToken;
                    const isAdmin = userRole === 'admin';

                    if (!isOwner && !isAdmin) {
                        console.warn(`Forbidden edit attempt on request ${requestId} by user ${userIdFromToken} (role: ${userRole}).`);
                        return res.status(403).json({ message: "Forbidden: You do not have permission to edit this request." });
                    }

                    // Define the fields that are allowed to be updated.
                    const updatableFields = ['recipientName', 'recipientEmail', 'recipientDistrict', 'recipientUpazila', 'bloodGroup', 'hospitalName', 'fullAddress', 'donorName', 'donorEmail', 'donationDate', 'donationTime', 'donationStatus'];
                    const updateDoc = { $set: {} };

                    // Populate the update document with allowed fields from the request body
                    updatableFields.forEach(field => {
                        if (updatedData[field] !== undefined) {
                            updateDoc.$set[field] = updatedData[field];
                        }
                    });

                    // Add a timestamp for the update
                    updateDoc.$set.updatedAt = new Date();

                    const result = await requestCollection.updateOne(query, updateDoc);

                    if (result.matchedCount === 0) {
                        return res.status(404).json({ message: "Donation request not found or no changes were made." });
                    }

                    res.status(200).json({ message: "Donation request updated successfully." });

                } catch (error) {
                    console.error('Backend: Error updating donation request:', error);
                    res.status(500).json({ message: 'Failed to update donation request', error: error.message });
                }
            });

            // Endpoint to update a donation request to 'pending' status with donor information
            // This endpoint is used when a donor claims a donation request.

            app.put('/claimRequest/:id', verifyFirebaseToken, async (req, res) => {
                const { id } = req.params;
                const { donorName, donorEmail } = req.body;

                // Basic input validation
                if (!donorName || !donorEmail) {
                    return res.status(400).json({ message: 'Donor name and email are required.' });
                }

                try {
                    // Use ObjectId to query by the document's ID
                    const donationRequest = await requestCollection.findOne({ _id: new ObjectId(id) });

                    // Check if the request exists
                    if (!donationRequest) {
                        return res.status(404).json({ message: 'Donation request not found.' });
                    }

                    // Check the current status. A request can only be claimed if its status is not 'inProgress' or 'completed'.
                    // This prevents multiple donors from claiming the same request.
                    if (donationRequest.donationStatus === 'inProgress' || donationRequest.donationStatus === 'completed') {
                        return res.status(409).json({ message: `This request has already been claimed and is no longer available.` });
                    }

                    // Prepare the update document
                    const updateDoc = {
                        $set: {
                            donationStatus: 'inProgress',
                            donorName: donorName,
                            donorEmail: donorEmail,
                            updatedAt: new Date(),
                        }
                    };

                    // Update the donation request with donor information and the new status
                    const result = await requestCollection.updateOne({ _id: new ObjectId(id) }, updateDoc);

                    if (result.matchedCount === 0) {
                        // This is a fail-safe, as the previous findOne should have caught this
                        return res.status(404).json({ message: 'Failed to update request, not found after initial check.' });
                    }

                    // Send a success response
                    res.status(200).json({
                        message: 'Donation request successfully updated.',
                        updatedCount: result.matchedCount,
                    });

                } catch (error) {
                    // Log the error for debugging
                    console.error('Error updating donation request:', error);
                    // Send a generic error response to the client
                    res.status(500).json({ message: 'An internal server error occurred while updating the request.' });
                }
            });

            // NEW: Endpoint to handle Stripe Payment Intents
            app.post('/create-payment-intent', async (req, res) => {
                try {
                    const { amount } = req.body;
                    if (typeof amount !== 'number' || amount <= 0) {
                        console.error('Invalid amount received for payment intent:', amount);
                        return res.status(400).json({ message: 'Invalid amount.' });
                    }
                    // console.log(`Creating a PaymentIntent for amount: $${(amount / 100).toFixed(2)}`);
                    const paymentIntent = await stripe.paymentIntents.create({
                        amount: amount,
                        currency: 'usd',
                        payment_method_types: ['card'],
                    });
                    res.status(200).json({
                        clientSecret: paymentIntent.client_secret,
                    });
                } catch (error) {
                    console.error('Error creating payment intent:', error);
                    res.status(500).json({
                        message: 'Failed to create payment intent.',
                        error: error.message,
                    });
                }
            });

        } finally {
            // Ensures that the client will close when you finish/error
            // await client.close(); // You may not want to close the connection in a serverless function
        }
    }
run().catch(console.dir);


    // Start the Express server
    app.listen(port, () => {
        console.log(`LifeStream Server is running on port ${port}`);
    });
