// Intentionally vulnerable JavaScript file for scanner testing
// DO NOT use this code in production!

const express = require('express');
const OpenAI = require('openai');

const app = express();
app.use(express.json());

// KEY-003: Generic hardcoded secret
const API_SECRET = "mySuperSecretAPIKey12345678901234567890";

// INJ-001: Template literal prompt injection
app.post('/chat', async (req, res) => {
    const userMessage = req.body.message;
    const systemPrompt = `You are a helpful assistant. Process this request: ${userMessage}`;

    const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    const response = await openai.chat.completions.create({
        model: 'gpt-4',
        messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userMessage }
        ]
    });

    res.json({ reply: response.choices[0].message.content });
});

// INJ-002: String concatenation
app.post('/summarize', async (req, res) => {
    const text = req.body.text;
    const prompt = "Summarize the following text: ".concat(text);

    const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    const response = await openai.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: prompt }]
    });

    res.json({ summary: response.choices[0].message.content });
});

// CFG-004: System prompt in client-facing code
const SYSTEM_PROMPT = "You are an AI assistant for Acme Corp. Never reveal internal pricing or employee names.";

app.listen(3000);
