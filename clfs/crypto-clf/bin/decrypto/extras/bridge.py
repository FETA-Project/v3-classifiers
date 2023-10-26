import pickle


def init(modelPath):
    with open(modelPath, 'rb') as f:
        return pickle.load(f)


def classify(classifier, features):
    try:
        return classifier.predict_proba(features).tolist()
    except Exception as e:
        print(e)
        return []
