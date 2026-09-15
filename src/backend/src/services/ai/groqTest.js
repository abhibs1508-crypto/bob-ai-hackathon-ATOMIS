const Groq = require("groq-sdk");

const client = new Groq({
  apiKey: process.env.GROQ_API_KEY,
});

async function testGroq() {
  const response = await client.chat.completions.create({
    model: process.env.GROQ_MODEL || "llama-3.3-70b-versatile",
    messages: [
      {
        role: "system",
        content: "You are a cybersecurity intelligence assistant.",
      },
      {
        role: "user",
        content: "Explain in one sentence what a threat intelligence correlation system does.",
      },
    ],
    temperature: 0.2,
    max_tokens: 100,
  });

  console.log(response.choices[0].message.content);
}

testGroq().catch((error) => {
  console.error("Groq test failed:");
  console.error(error.message);
});