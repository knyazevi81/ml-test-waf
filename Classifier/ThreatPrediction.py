import pandas as pd
import joblib
import matplotlib.pyplot as plt
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import SVC


if __name__ == '__main__':
    print('Training Threat Prediction Classifier\n')
    print('Loading data...')
    data_df = pd.read_json('../Dataset/complete_clean.json')
    counts = data_df['type'].value_counts()
    print(counts)
    X = data_df['pattern'].to_numpy().astype(str)
    y = data_df['type'].to_numpy().astype(str)
    print("Data loaded")
    print(f"X: {len(X)}, Y: {len(y)}")

    print("Splitting the dataset...")
    trainX, testX, trainY, testY = train_test_split(X, y, test_size = 0.25, random_state = 42, stratify = y)
    print(f"TrainX: {len(trainX)}, TrainY: {len(trainY)}, TestX: {len(testX)}, TestY: {len(testY)}")
    print("Dataset splitted")

    # Hyperparameter tuning to find the best configuration for a text classification model using a Support Vector Classifier and TF-IDF vectorization.
    ## The process begins by creating a pipeline that includes a TfidfVectorizer and an SVC model. 
    ## The TfidfVectorizer is configured to analyze character-level n-grams and has a maximum feature limit of 1024.
    pipe = make_pipeline(TfidfVectorizer(input = 'content', lowercase = True, analyzer = 'char', max_features = 1024), SVC())
    param_grid = {'tfidfvectorizer__ngram_range': [(1, 1), (1, 2), (1, 4)], 'svc__C': [1, 10], 'svc__kernel': ['linear', 'rbf']}
    grid = GridSearchCV(pipe, param_grid, cv = 2, verbose = 4)
    grid.fit(trainX, trainY)
    grid.score(testX, testY)
    preds = grid.predict(testX)
    # Classification report
    print(classification_report(testY, preds))
    print("Best Parameters: ", grid.best_params_)

    # Create a pipeline with the optimal configuration and save the model
    pipe = make_pipeline(TfidfVectorizer(input = 'content', lowercase = True, analyzer = 'char', max_features = 1024, ngram_range = grid.best_params_['tfidfvectorizer__ngram_range']), 
                         SVC(C = grid.best_params_['svc__C'], kernel = grid.best_params_['svc__kernel']), 
                         verbose=True)
    print("Training model...")
    pipe.fit(trainX, trainY)
    pipe.score(testX, testY)
    print("Model trained")
    print("Testing model...")
    preds = pipe.predict(testX)
    print(classification_report(testY, preds))
    cm = confusion_matrix(testY, preds, labels=pipe.classes_)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=pipe.classes_)
    plt.savefig('confusion_matrix.png')
    
    print("Model tested")
    print("Saving model...")
    joblib.dump(pipe, 'predictor.joblib')
    print("Model trained and saved as predictor.joblib")
