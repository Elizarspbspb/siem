inputs = tokenizer("openssl 1.0.1u", return_tensors="pt")
outputs = model(**inputs).logits
predictions = outputs.argmax(dim=2)
# Далее можно интерпретировать результат и извлечь версии

