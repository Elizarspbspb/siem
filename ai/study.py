from transformers import AutoTokenizer, AutoModelForTokenClassification, TrainingArguments, Trainer
from datasets import load_dataset

# Загрузка данных
dataset = load_dataset('json', data_files='data.json')
train_dataset = dataset['train']

# Загрузка предобученного токенизатора и модели
model_name = "bert-base-uncased"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForTokenClassification.from_pretrained(model_name, num_labels=2)  # 2 метки: версия или нет

# Подготовка данных для обучения
def tokenize_and_align_labels(examples):
    tokenized_inputs = tokenizer(examples["text"], truncation=True, padding=True, max_length=128)
    labels = [[1 if word in example["versions"] else 0 for word in examples["text"].split()] for example in examples]
    tokenized_inputs["labels"] = labels
    return tokenized_inputs

tokenized_datasets = train_dataset.map(tokenize_and_align_labels, batched=True)

# Определение аргументов для тренировки
training_args = TrainingArguments(
    output_dir="./results",
    evaluation_strategy="epoch",
    learning_rate=2e-5,
    per_device_train_batch_size=16,
    num_train_epochs=3,
    weight_decay=0.01,
)

# Создание и обучение модели
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=tokenized_datasets,
)

trainer.train()

