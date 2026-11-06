import express from 'express'
import { MongoClient, ObjectId } from 'mongodb'
import cors from 'cors'
import 'dotenv/config'
import { createRemoteJWKSet, jwtVerify } from 'jose'

const app = express()
const PORT = 8000
const BORROW_DAYS = 7

app.use(cors())
app.use(express.json())

const client = new MongoClient(process.env.MONGODB_URI)

export async function connectToMongoDB() {
  try {
    await client.connect()
    console.log('You successfully connected to MongoDB!')
    return client
  } catch (err) {
    console.dir(err)
  }
}

const mongoClient = await connectToMongoDB()

const db = mongoClient.db('book-nook')
const bookCollection = db.collection('books')
const borrowCollection = db.collection('borrowedBooks')

// Created once, so the keys are cached between requests.
const JWKS = createRemoteJWKSet(
  new URL(`${process.env.CLIENT_URL}/api/auth/jwks`)
)

const verifyToken = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(401).send({ message: 'Unauthorized.' })

  try {
    const { payload } = await jwtVerify(token, JWKS)
    // Better Auth puts the user (id, name, email, image...) in the payload.
    req.user = payload
    next()
  } catch {
    return res.status(401).send({ message: 'Invalid or expired token.' })
  }
}

app.get('/', (req, res) => {
  res.send({ message: 'Server is running fine!' })
})

// ---------- Books ----------

// Public: newest first, optional ?limit=
app.get('/books', async (req, res) => {
  const limit = Number(req.query.limit) || 0
  const result = await bookCollection
    .find()
    .sort({ _id: -1 })
    .limit(limit)
    .toArray()
  res.send(result)
})

app.get('/books/:id', verifyToken, async (req, res) => {
  const { id } = req.params
  if (!ObjectId.isValid(id)) {
    return res.status(400).send({ message: 'Invalid book id.' })
  }

  const book = await bookCollection.findOne({ _id: new ObjectId(id) })
  if (!book) return res.status(404).send({ message: 'Book not found.' })

  res.send(book)
})

app.post('/add-book', verifyToken, async (req, res) => {
  const { title, author, category, copies, imageUrl, description } = req.body

  const total = Number(copies)
  if (!title || !author || !category || !Number.isInteger(total) || total < 1) {
    return res.status(400).send({ message: 'Please fill in all required fields.' })
  }

  const result = await bookCollection.insertOne({
    title,
    author,
    category,
    copies: total,
    imageUrl: imageUrl ?? '',
    description: description ?? '',
    // Always taken from the token, never from the request body.
    userName: req.user.name,
    userEmail: req.user.email,
  })

  res.send(result)
})

// Books added by the logged-in user
app.get('/my-books', verifyToken, async (req, res) => {
  const result = await bookCollection
    .find({ userEmail: req.user.email })
    .sort({ _id: -1 })
    .toArray()
  res.send(result)
})

// Edit a book (owner only)
app.put('/books/:id', verifyToken, async (req, res) => {
  const { id } = req.params
  if (!ObjectId.isValid(id)) {
    return res.status(400).send({ message: 'Invalid book id.' })
  }

  const book = await bookCollection.findOne({ _id: new ObjectId(id) })
  if (!book) return res.status(404).send({ message: 'Book not found.' })
  if (book.userEmail !== req.user.email) {
    return res.status(403).send({ message: 'You can only edit your own books.' })
  }

  // Only these fields can be changed.
  const { title, author, category, copies, imageUrl, description } = req.body
  const update = { title, author, category, imageUrl, description }

  if (copies !== undefined) {
    const total = Number(copies)
    if (!Number.isInteger(total) || total < 0) {
      return res.status(400).send({ message: 'Copies must be a whole number.' })
    }
    update.copies = total
  }

  // Drop anything that wasn't sent.
  Object.keys(update).forEach((key) => update[key] === undefined && delete update[key])

  await bookCollection.updateOne({ _id: book._id }, { $set: update })
  res.send(await bookCollection.findOne({ _id: book._id }))
})

// Delete a book (owner only)
app.delete('/books/:id', verifyToken, async (req, res) => {
  const { id } = req.params
  if (!ObjectId.isValid(id)) {
    return res.status(400).send({ message: 'Invalid book id.' })
  }

  const book = await bookCollection.findOne({ _id: new ObjectId(id) })
  if (!book) return res.status(404).send({ message: 'Book not found.' })
  if (book.userEmail !== req.user.email) {
    return res.status(403).send({ message: 'You can only delete your own books.' })
  }

  const result = await bookCollection.deleteOne({ _id: book._id })
  res.send(result)
})

// ---------- Borrowing ----------

app.post('/borrow', verifyToken, async (req, res) => {
  const { bookId } = req.body
  const userEmail = req.user.email
  const userName = req.user.name

  if (!ObjectId.isValid(bookId)) {
    return res.status(400).send({ message: 'Invalid book id.' })
  }

  const book = await bookCollection.findOne({ _id: new ObjectId(bookId) })
  if (!book) return res.status(404).send({ message: 'Book not found.' })

  const alreadyBorrowed = await borrowCollection.findOne({ bookId, userEmail })
  if (alreadyBorrowed) {
    return res.status(409).send({ message: 'You have already borrowed this book.' })
  }


  const decrement = await bookCollection.updateOne(
    { _id: new ObjectId(bookId), copies: { $gt: 0 } },
    { $inc: { copies: -1 } }
  )
  if (decrement.modifiedCount === 0) {
    return res.status(409).send({ message: 'No copies available right now.' })
  }

  const borrowDate = new Date()
  const returnDate = new Date(borrowDate)
  returnDate.setDate(returnDate.getDate() + BORROW_DAYS)

  try {
    const result = await borrowCollection.insertOne({
      bookId,
      title: book.title,
      author: book.author,
      imageUrl: book.imageUrl ?? '',
      userName,
      userEmail,
      borrowDate: borrowDate.toISOString(),
      returnDate: returnDate.toISOString(),
    })
    res.send(result)
  } catch (error) {

    await bookCollection.updateOne({ _id: new ObjectId(bookId) }, { $inc: { copies: 1 } })
    res.status(500).send({ message: 'Could not borrow the book.' })
  }
})


app.get('/my-borrows', verifyToken, async (req, res) => {
  const result = await borrowCollection
    .find({ userEmail: req.user.email })
    .sort({ _id: -1 })
    .toArray()
  res.send(result)
})


app.delete('/borrow/:id', verifyToken, async (req, res) => {
  const { id } = req.params
  if (!ObjectId.isValid(id)) {
    return res.status(400).send({ message: 'Invalid borrow id.' })
  }

  const borrow = await borrowCollection.findOne({ _id: new ObjectId(id) })
  if (!borrow) return res.status(404).send({ message: 'Borrow record not found.' })
  if (borrow.userEmail !== req.user.email) {
    return res.status(403).send({ message: 'This is not your borrowed book.' })
  }

  const removed = await borrowCollection.deleteOne({ _id: borrow._id })

  
  if (removed.deletedCount === 1 && ObjectId.isValid(borrow.bookId)) {
    await bookCollection.updateOne(
      { _id: new ObjectId(borrow.bookId) },
      { $inc: { copies: 1 } }
    )
  }

  res.send({ success: true })
})

app.listen(PORT, () => {
  console.log(`Server is running at ${PORT}`)
})

export default app